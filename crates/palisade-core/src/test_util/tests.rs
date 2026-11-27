use alloc::{string::ToString, vec, vec::Vec};

use super::*;
use crate::platform::{
    AccountName, Elevation, GroupMembership, IntegrityLevel, SessionKind, ancestry, expand_env_vars,
};

const START: UtcTime = UtcTime(1_764_000_000_000_000); // 2025-11-24

fn record(pid: u32, created: i64, parent: Option<u32>, image: &str) -> ProcessRecord {
    ProcessRecord {
        key: ProcessKey {
            pid,
            created: UtcTime(created),
        },
        parent_pid: parent,
        image_path: image.to_string(),
        command_line: None,
    }
}

// ---------------------------------------------------------------- clock

#[test]
fn mock_clock_meets_the_contract() {
    let clock = MockClock::new(START, MonotonicTime(5));
    contract::clock(&clock).unwrap();
}

#[test]
fn mock_clock_advances_both_clocks_and_set_moves_only_the_wall_clock() {
    let clock = MockClock::new(START, MonotonicTime(0));
    clock.advance(1_500_000);
    assert_eq!(clock.now_utc(), UtcTime(START.0 + 1_500_000));
    assert_eq!(clock.monotonic(), MonotonicTime(1_500_000));
    assert_eq!(clock.monotonic().secs(), 1);
    clock.set_utc(UtcTime(START.0 - 86_400_000_000));
    assert_eq!(clock.now_utc().0, START.0 - 86_400_000_000);
    assert_eq!(clock.monotonic(), MonotonicTime(1_500_000));
}

#[test]
fn mock_clock_saturates() {
    let clock = MockClock::new(UtcTime(i64::MAX - 1), MonotonicTime(u64::MAX - 1));
    clock.advance(u64::MAX);
    assert_eq!(clock.now_utc(), UtcTime(i64::MAX));
    assert_eq!(clock.monotonic(), MonotonicTime(u64::MAX));
}

#[test]
fn contract_rejects_an_implausible_clock() {
    let clock = MockClock::new(UtcTime(0), MonotonicTime(0));
    assert!(contract::clock(&clock).is_err());
}

#[test]
fn utc_seconds_round_down() {
    assert_eq!(UtcTime(1_999_999).unix_secs(), 1);
    assert_eq!(UtcTime(-1).unix_secs(), -1);
    assert_eq!(
        UtcTime(i64::MAX).saturating_add_micros(1),
        UtcTime(i64::MAX)
    );
}

// ---------------------------------------------------------------- files

/// A self-relative descriptor header (revision 1,
/// `SE_DACL_PRESENT | SE_SELF_RELATIVE`), with no owner, group or ACLs.
fn sample_descriptor() -> Vec<u8> {
    let mut sd = vec![1_u8, 0, 4, 0x80];
    sd.extend([0_u8; 16]);
    sd
}

fn sample_fs() -> MockFileSystem {
    let mut fs = MockFileSystem::new();
    fs.insert(
        r"C:\Tools\tool.exe",
        MockFile::new(b"MZ example contents".to_vec())
            .owner("S-1-5-32-544")
            .descriptor(sample_descriptor())
            .stream(
                "Zone.Identifier",
                b"[ZoneTransfer]\r\nZoneId=3\r\n".to_vec(),
            )
            .metadata(FileMetadata {
                file_id: Some(42),
                volume_serial: Some(0xABCD),
                usn: Some(7),
                ..FileMetadata::default()
            }),
    );
    fs.insert(r"C:\Tools", MockFile::directory());
    fs
}

#[test]
fn mock_file_system_meets_the_contract() {
    let fs = sample_fs();
    contract::file_system(
        &fs,
        r"C:\Tools\tool.exe",
        b"MZ example contents",
        r"C:\nope.exe",
    )
    .unwrap();
    // Case-insensitive, as on Windows.
    contract::file_system(
        &fs,
        r"c:\tools\TOOL.EXE",
        b"MZ example contents",
        r"C:\nope",
    )
    .unwrap();
    contract::directory(&fs, r"C:\Tools").unwrap();
    assert!(contract::directory(&fs, r"C:\Tools\tool.exe").is_err());
}

#[test]
fn contract_catches_a_file_system_that_returns_the_wrong_contents() {
    let fs = sample_fs();
    assert!(contract::file_system(&fs, r"C:\Tools\tool.exe", b"other", r"C:\nope").is_err());
    assert!(
        contract::file_system(
            &fs,
            r"C:\Tools\tool.exe",
            b"MZ example contents",
            r"C:\Tools"
        )
        .is_err(),
        "an existing path passed as missing"
    );
}

#[test]
fn mock_files_report_metadata_owner_descriptor_and_streams() {
    let fs = sample_fs();
    let file = fs.open(r"C:\Tools\tool.exe").unwrap();
    let meta = file.metadata().unwrap();
    assert_eq!(meta.size, 19);
    assert_eq!(meta.file_id, Some(42));
    assert_eq!(meta.volume_serial, Some(0xABCD));
    assert_eq!(meta.usn, Some(7));
    assert_eq!(
        fs.owner_sid(r"C:\Tools\tool.exe").unwrap().as_deref(),
        Some("S-1-5-32-544")
    );
    assert_eq!(
        fs.security_descriptor(r"C:\Tools\tool.exe").unwrap(),
        Some(sample_descriptor())
    );
    let streams = fs.streams(r"C:\Tools\tool.exe").unwrap();
    assert_eq!(streams.len(), 1);
    assert_eq!(streams[0].name, "Zone.Identifier");
    assert_eq!(streams[0].size, 26);
    assert_eq!(fs.owner_sid(r"C:\Tools").unwrap(), None);
    assert_eq!(
        fs.owner_sid(r"C:\missing").unwrap_err().kind(),
        ErrorKind::NotFound
    );
}

#[test]
fn mock_streams_open_by_name_with_or_without_the_type() {
    let fs = sample_fs();
    for path in [
        r"C:\Tools\tool.exe:Zone.Identifier",
        r"C:\Tools\tool.exe:zone.identifier:$DATA",
    ] {
        let mut file = fs.open(path).unwrap();
        let mut buf = [0u8; 14];
        assert_eq!(file.read_at(0, &mut buf).unwrap(), 14);
        assert_eq!(&buf, b"[ZoneTransfer]");
        assert_eq!(file.metadata().unwrap().size, 26);
    }
    // The main stream, named explicitly.
    let mut main = fs.open(r"C:\Tools\tool.exe::$DATA").unwrap();
    let mut buf = [0u8; 2];
    main.read_at(0, &mut buf).unwrap();
    assert_eq!(&buf, b"MZ");
    assert_eq!(
        fs.open(r"C:\Tools\tool.exe:other").unwrap_err().kind(),
        ErrorKind::NotFound
    );
}

#[test]
fn drive_letters_are_not_streams() {
    use StreamPart::{Invalid, Main, Named, None};
    for (path, base, part) in [
        (r"C:\a\b", r"C:\a\b", None),
        ("C:", "C:", None),
        (r"C:\a\b:s", r"C:\a\b", Named("s")),
        ("b:s", "b:s", None),
        (r"\\srv\share\f:s", r"\\srv\share\f", Named("s")),
        (r"C:\a\b:s:$Data", r"C:\a\b", Named("s")),
        (r"C:\a\b::$data", r"C:\a\b", Main),
        (r"C:\a\b:", r"C:\a\b", Invalid),
        (r"C:\a\b:s:$BITMAP", r"C:\a\b", Invalid),
        (r"C:\a\b:s:", r"C:\a\b", Invalid),
    ] {
        assert_eq!(split_stream(path), (base, part), "{path}");
    }
}

#[test]
fn streams_on_directories_and_malformed_stream_paths() {
    let mut fs = sample_fs();
    fs.insert(r"C:\Tools:note", MockFile::new(b"dir stream".to_vec()));
    // A named stream of a directory is data that can be read.
    let mut s = fs.open(r"C:\Tools:note").unwrap();
    let meta = s.metadata().unwrap();
    assert!(!meta.is_dir);
    assert_eq!(meta.size, 10);
    let mut buf = [0u8; 10];
    assert_eq!(s.read_at(0, &mut buf).unwrap(), 10);
    assert_eq!(&buf, b"dir stream");
    // The directory itself is still a directory, with the stream listed.
    assert!(fs.open(r"C:\Tools").unwrap().metadata().unwrap().is_dir);
    assert_eq!(fs.streams(r"C:\Tools").unwrap()[0].name, "note");
    // A directory has no unnamed data stream; `file:` is malformed.
    assert_eq!(
        fs.open(r"C:\Tools::$DATA").unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        fs.open(r"C:\Tools\tool.exe:").unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(
        fs.open(r"C:\missing.txt:").unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert!(fs.open(r"C:\Tools\tool.exe::$DATA").is_ok());
    // Owners, descriptors and stream lists belong to the base file.
    assert_eq!(
        fs.owner_sid(r"C:\Tools\tool.exe:Zone.Identifier")
            .unwrap()
            .as_deref(),
        Some("S-1-5-32-544")
    );
    assert!(
        fs.security_descriptor(r"C:\Tools\tool.exe::$DATA")
            .unwrap()
            .is_some()
    );
    assert_eq!(
        fs.owner_sid(r"C:\Tools\tool.exe:").unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    // Inserting at a stream path adds a stream, not a separate file.
    fs.insert(r"C:\new.txt:evil.exe", MockFile::new(b"MZ".to_vec()));
    assert_eq!(fs.open(r"C:\new.txt").unwrap().metadata().unwrap().size, 0);
    assert_eq!(
        fs.open(r"C:\new.txt:evil.exe")
            .unwrap()
            .metadata()
            .unwrap()
            .size,
        2
    );
    fs.insert(r"C:\new.txt::$DATA", MockFile::new(b"main".to_vec()));
    assert_eq!(fs.open(r"C:\new.txt").unwrap().metadata().unwrap().size, 4);
}

#[test]
fn directories_open_but_cannot_be_read_and_removed_files_are_gone() {
    let mut fs = sample_fs();
    let mut dir = fs.open(r"C:\Tools").unwrap();
    assert!(dir.metadata().unwrap().is_dir);
    assert_eq!(dir.metadata().unwrap().size, 0);
    assert_eq!(
        dir.read_at(0, &mut [0u8; 4]).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert!(fs.remove(r"c:\tools\tool.exe").is_some());
    assert_eq!(
        fs.open(r"C:\Tools\tool.exe").unwrap_err().kind(),
        ErrorKind::NotFound
    );
}

#[test]
fn reads_past_the_end_and_huge_offsets_return_nothing() {
    let fs = sample_fs();
    let mut file = fs.open(r"C:\Tools\tool.exe").unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(file.read_at(17, &mut buf).unwrap(), 2);
    assert_eq!(file.read_at(19, &mut buf).unwrap(), 0);
    assert_eq!(file.read_at(u64::MAX, &mut buf).unwrap(), 0);
    assert_eq!(file.read_at(0, &mut []).unwrap(), 0);
}

// ---------------------------------------------------------------- signatures

#[test]
fn mock_signatures_return_scripted_chains() {
    let mut sigs = MockSignatures::new();
    let result = SignatureResult {
        source: crate::platform::SignatureSource::Embedded,
        status: crate::VerificationError::Ok,
        chain: vec![crate::platform::CertificateSummary {
            subject: "Example Software Ltd".into(),
            issuer: "Example Code Signing CA".into(),
            sha256: [7; 32],
        }],
        signing_time: Some(START),
    };
    sigs.set_embedded(r"C:\Tools\tool.exe", vec![result.clone()]);
    let catalog = SignatureResult {
        source: crate::platform::SignatureSource::Catalog,
        status: crate::VerificationError::UntrustedRoot,
        ..result.clone()
    };
    sigs.set_catalog(r"C:\Tools\tool.exe", catalog.clone());
    assert_eq!(sigs.embedded(r"c:\TOOLS\tool.exe").unwrap(), vec![result]);
    assert_eq!(sigs.catalog(r"C:\Tools\tool.exe").unwrap(), Some(catalog));
    assert!(sigs.embedded(r"C:\other.exe").unwrap().is_empty());
    assert_eq!(sigs.catalog(r"C:\other.exe").unwrap(), None);
}

#[test]
fn mock_signatures_meet_the_contract() {
    let leaf = crate::platform::CertificateSummary {
        subject: "Example Signer".into(),
        issuer: "Example Root".into(),
        sha256: [1; 32],
    };
    let root = crate::platform::CertificateSummary {
        subject: "Example Root".into(),
        issuer: "Example Root".into(),
        sha256: [2; 32],
    };
    let ok = SignatureResult {
        source: crate::platform::SignatureSource::Embedded,
        status: crate::VerificationError::Ok,
        chain: vec![leaf.clone(), root.clone()],
        signing_time: None,
    };
    let mut sigs = MockSignatures::new();
    sigs.set_embedded(r"C:\signed.exe", vec![ok.clone()]);
    sigs.set_missing(r"C:\missing.exe");
    contract::signatures(&sigs, r"C:\signed.exe", r"C:\plain.exe", r"C:\missing.exe").unwrap();

    // A missing file read as unsigned, a broken chain, or a status that
    // is not Ok breaks the contract.
    let mut lax = MockSignatures::new();
    lax.set_embedded(r"C:\signed.exe", vec![ok.clone()]);
    assert!(contract::signatures(&lax, r"C:\signed.exe", r"C:\plain.exe", r"C:\gone.exe").is_err());
    let mut broken = MockSignatures::new();
    broken.set_missing(r"C:\missing.exe");
    broken.set_embedded(
        r"C:\signed.exe",
        vec![SignatureResult {
            chain: vec![root, leaf],
            ..ok.clone()
        }],
    );
    assert!(
        contract::signatures(
            &broken,
            r"C:\signed.exe",
            r"C:\plain.exe",
            r"C:\missing.exe"
        )
        .is_err()
    );
    let mut weak = MockSignatures::new();
    weak.set_missing(r"C:\missing.exe");
    weak.set_embedded(
        r"C:\signed.exe",
        vec![SignatureResult {
            status: crate::VerificationError::WeakHashAlgorithm,
            ..ok
        }],
    );
    assert!(
        contract::signatures(&weak, r"C:\signed.exe", r"C:\plain.exe", r"C:\missing.exe").is_err()
    );
}

// ---------------------------------------------------------------- identity

fn token(user: &str) -> TokenInfo {
    TokenInfo {
        user_sid: user.to_string(),
        groups: vec![GroupMembership {
            sid: "S-1-5-32-544".into(),
            deny_only: true,
        }],
        session_id: 2,
        session_kind: SessionKind::RemoteDesktop,
        integrity: IntegrityLevel::Medium,
        elevation: Elevation::Limited,
        elevated: false,
    }
}

#[test]
fn mock_identity_meets_the_contract() {
    let mut id = MockIdentity::new();
    let key = ProcessKey {
        pid: 100,
        created: START,
    };
    let system = TokenInfo {
        session_id: 0,
        session_kind: SessionKind::Services,
        integrity: IntegrityLevel::System,
        elevation: Elevation::Default,
        elevated: true,
        ..token("S-1-5-18")
    };
    id.set_current(system);
    id.set_token(key, token("S-1-5-21-1-2-3-1001"));
    id.set_local_group("S-1-5-32-544", vec!["S-1-5-21-1-2-3-500".into()]);
    contract::identity(&id, key, "S-1-5-32-544", "s-1-5-21-1-2-3-500").unwrap();
    assert!(contract::identity(&id, key, "S-1-5-32-544", "S-1-5-18").is_err());

    // Tokens that break the rules.
    let breaks = |t: TokenInfo| {
        let mut id = MockIdentity::new();
        id.set_current(t);
        id.set_token(key, token("S-1-5-21-1-2-3-1001"));
        id.set_local_group("S-1-5-32-544", vec!["S-1-5-18".into()]);
        contract::identity(&id, key, "S-1-5-32-544", "S-1-5-18").is_err()
    };
    assert!(!breaks(token("S-1-0x00000000000F-1")));
    assert!(breaks(token("alice")));
    assert!(breaks(token("S-1-5-x")));
    assert!(breaks(TokenInfo {
        session_id: 0,
        ..token("S-1-5-18")
    }));
    assert!(breaks(TokenInfo {
        elevation: Elevation::Full,
        elevated: false,
        ..token("S-1-5-18")
    }));
    assert!(breaks(TokenInfo {
        groups: vec![GroupMembership {
            sid: "S-1-16-8192".into(),
            deny_only: false,
        }],
        ..token("S-1-5-18")
    }));
}

#[test]
fn mock_identity_returns_scripted_tokens_and_groups() {
    let mut id = MockIdentity::new();
    assert_eq!(id.current().unwrap_err().kind(), ErrorKind::NotFound);
    id.set_current(token("S-1-5-18"));
    let key = ProcessKey {
        pid: 100,
        created: START,
    };
    id.set_token(key, token("S-1-5-21-1-2-3-1001"));
    id.set_local_group("S-1-5-32-544", vec!["S-1-5-21-1-2-3-500".into()]);
    id.set_directory_groups(
        "S-1-5-21-1-2-3-1001",
        DirectoryGroups {
            groups: vec!["0f1e2d3c-0000-4000-8000-000000000001".into()],
            fetched_at: START,
        },
    );
    id.set_account_name(
        "S-1-5-21-1-2-3-1001",
        AccountName {
            domain: Some("EXAMPLE".into()),
            name: "alice".into(),
        },
    );
    assert_eq!(
        id.account_name("s-1-5-21-1-2-3-1001")
            .unwrap()
            .unwrap()
            .name,
        "alice"
    );
    assert_eq!(id.account_name("S-1-5-18").unwrap(), None);
    assert_eq!(id.current().unwrap().user_sid, "S-1-5-18");
    let t = id.token(key).unwrap();
    assert_eq!(t.session_kind, SessionKind::RemoteDesktop);
    assert!(t.groups[0].deny_only);
    let reused = ProcessKey {
        pid: 100,
        created: UtcTime(START.0 + 1),
    };
    assert_eq!(id.token(reused).unwrap_err().kind(), ErrorKind::NotFound);
    assert_eq!(id.local_group_members("s-1-5-32-544").unwrap().len(), 1);
    assert!(id.local_group_members("S-1-5-32-545").is_err());
    let cached = id.directory_groups("S-1-5-21-1-2-3-1001").unwrap().unwrap();
    assert_eq!(cached.fetched_at, START);
    assert_eq!(id.directory_groups("S-1-5-18").unwrap(), None);
}

// ---------------------------------------------------------------- processes

#[test]
fn mock_processes_meet_the_contract() {
    let procs = MockProcesses::new();
    procs.start(record(4, 10, None, "System"));
    procs.start(record(
        600,
        20,
        Some(4),
        r"C:\Windows\System32\services.exe",
    ));
    procs.start(record(1200, 30, Some(600), r"C:\Windows\explorer.exe"));
    let key = ProcessKey {
        pid: 1200,
        created: UtcTime(30),
    };
    contract::processes(&procs, key).unwrap();
    let chain = ancestry(&procs, key).unwrap();
    let pids: Vec<u32> = chain.iter().map(|r| r.key.pid).collect();
    assert_eq!(pids, [600, 4]);
}

#[test]
fn ancestry_stops_at_a_reused_parent_id() {
    let procs = MockProcesses::new();
    // The child's real parent, PID 500, exited; a newer process took 500.
    procs.start(record(500, 100, None, r"C:\unrelated.exe"));
    procs.start(record(900, 50, Some(500), r"C:\child.exe"));
    let key = ProcessKey {
        pid: 900,
        created: UtcTime(50),
    };
    assert!(ancestry(&procs, key).unwrap().is_empty());
    contract::processes(&procs, key).unwrap();
}

#[test]
fn ancestry_stops_at_an_exited_parent_a_loop_and_the_limit() {
    let procs = MockProcesses::new();
    procs.start(record(7, 5, Some(99), r"C:\orphan.exe"));
    let key = ProcessKey {
        pid: 7,
        created: UtcTime(5),
    };
    assert!(ancestry(&procs, key).unwrap().is_empty());

    // A loop: 1's parent is 2, 2's parent is 1, same creation time.
    procs.start(record(1, 5, Some(2), "a"));
    procs.start(record(2, 5, Some(1), "b"));
    let one = ProcessKey {
        pid: 1,
        created: UtcTime(5),
    };
    assert_eq!(ancestry(&procs, one).unwrap().len(), 1);

    // A chain longer than the limit.
    for pid in 1000..1100u32 {
        procs.start(record(pid, i64::from(pid), Some(pid - 1), "x"));
    }
    let deep = ProcessKey {
        pid: 1099,
        created: UtcTime(1099),
    };
    assert_eq!(
        ancestry(&procs, deep).unwrap().len(),
        crate::platform::MAX_ANCESTRY
    );
}

#[test]
fn an_exited_process_is_not_found() {
    let procs = MockProcesses::new();
    procs.start(record(3, 1, None, "a"));
    procs.exit(3);
    let key = ProcessKey {
        pid: 3,
        created: UtcTime(1),
    };
    assert_eq!(procs.get(key).unwrap_err().kind(), ErrorKind::NotFound);
    assert!(ancestry(&procs, key).is_err());
}

// ---------------------------------------------------------------- environment

#[test]
fn mock_environment_meets_the_contract() {
    let mut env = MockEnvironment::new();
    env.set_var("ProgramData", r"C:\ProgramData");
    contract::environment(&env, "ProgramData", r"C:\ProgramData", "NOT_SET").unwrap();
    assert_eq!(env.architecture(), Architecture::X64);
    assert_eq!(env.os_version().unwrap().to_string(), "10.0.26100.1");
    assert_eq!(env.connection_type().unwrap(), ConnectionType::Offline);
    assert!(env.addresses().unwrap().is_empty());
    assert_eq!(env.domain().unwrap(), None);
}

#[test]
fn contract_catches_case_sensitive_variables() {
    struct CaseSensitive;
    impl Environment for CaseSensitive {
        fn hostname(&self) -> Result<String> {
            Ok("h".into())
        }
        fn domain(&self) -> Result<Option<String>> {
            Ok(None)
        }
        fn os_version(&self) -> Result<OsVersion> {
            Err(PlatformError::new(ErrorKind::Unsupported, "n/a"))
        }
        fn architecture(&self) -> Architecture {
            Architecture::Other
        }
        fn addresses(&self) -> Result<Vec<InterfaceAddress>> {
            Ok(Vec::new())
        }
        fn connection_type(&self) -> Result<ConnectionType> {
            Ok(ConnectionType::Unknown)
        }
        fn var(&self, name: &str) -> Option<String> {
            (name == "Path").then(|| "x".into())
        }
    }
    assert!(contract::environment(&CaseSensitive, "Path", "x", "NOPE").is_err());
}

#[test]
fn expansion_follows_the_windows_rules() {
    let lookup = |name: &str| match name {
        "A" => Some("1".to_string()),
        "P" => Some("%A%".to_string()),
        "E" => Some(String::new()),
        _ => None,
    };
    for (input, expected) in [
        ("", ""),
        ("plain", "plain"),
        ("%A%", "1"),
        ("x%A%y%A%z", "x1y1z"),
        ("%B%", "%B%"),
        ("%B%%A%", "%B%1"),
        ("%%", "%%"),
        ("100%", "100%"),
        ("%A", "%A"),
        ("a%%A%", "a%%A%"),
        ("%P%", "%A%"),
        ("[%E%]", "[]"),
        ("%A%%", "1%"),
    ] {
        assert_eq!(expand_env_vars(input, lookup).unwrap(), expected, "{input}");
    }
}

#[test]
fn expansion_is_bounded() {
    let big = "x".repeat(crate::platform::MAX_EXPANDED_CHARS);
    let lookup = |_: &str| Some(big.clone());
    assert!(expand_env_vars("%A%", lookup).is_ok());
    assert_eq!(
        expand_env_vars("%A%.", lookup),
        Err(crate::platform::ExpandError::TooLong)
    );
    assert!(expand_env_vars("%A%%A%", lookup).is_err());
}

// ---------------------------------------------------------------- registry

#[test]
fn mock_registry_is_a_case_insensitive_map() {
    let mut reg = MockRegistry::new();
    reg.set_value(
        Hive::LocalMachine,
        r"SOFTWARE\Palisade\Agent",
        "ComputerTag",
        RegistryValue::String("lab".into()),
    );
    reg.set_value(
        Hive::LocalMachine,
        r"SOFTWARE\Palisade",
        "",
        RegistryValue::Dword(1),
    );
    reg.create_key(Hive::LocalMachine, r"SOFTWARE\Palisade\Cache");
    reg.set_value(
        Hive::Users,
        r"S-1-5-21-1-2-3-1001\Software",
        "x",
        RegistryValue::Qword(2),
    );

    assert!(
        reg.key_exists(Hive::LocalMachine, r"software\palisade")
            .unwrap()
    );
    assert!(
        reg.key_exists(Hive::LocalMachine, r"SOFTWARE\Palisade\")
            .unwrap()
    );
    assert!(!reg.key_exists(Hive::Users, r"SOFTWARE\Palisade").unwrap());
    assert_eq!(
        reg.value(
            Hive::LocalMachine,
            r"SOFTWARE\PALISADE\agent",
            "computertag"
        )
        .unwrap(),
        Some(RegistryValue::String("lab".into()))
    );
    assert_eq!(
        reg.value(Hive::LocalMachine, r"SOFTWARE\Palisade", "")
            .unwrap(),
        Some(RegistryValue::Dword(1))
    );
    assert_eq!(
        reg.value(Hive::LocalMachine, r"SOFTWARE\Palisade", "none")
            .unwrap(),
        None
    );
    assert_eq!(
        reg.value(Hive::LocalMachine, r"SOFTWARE\Missing", "x")
            .unwrap(),
        None
    );
    let mut subkeys = reg
        .subkeys(Hive::LocalMachine, r"Software\Palisade")
        .unwrap();
    subkeys.sort();
    assert_eq!(subkeys, ["Agent", "Cache"]);
    assert_eq!(
        reg.subkeys(Hive::Users, "").unwrap(),
        ["S-1-5-21-1-2-3-1001"]
    );
    assert_eq!(
        reg.subkeys(Hive::LocalMachine, r"SOFTWARE\Missing")
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
}

#[test]
fn mock_registry_meets_the_contract() {
    let mut reg = MockRegistry::new();
    reg.set_value(
        Hive::LocalMachine,
        r"SYSTEM\Select",
        "Current",
        RegistryValue::Dword(1),
    );
    reg.create_key(Hive::LocalMachine, r"SYSTEM\Select\Child");
    contract::registry(
        &reg,
        Hive::LocalMachine,
        r"SYSTEM\Select",
        "Current",
        &RegistryValue::Dword(1),
    )
    .unwrap();
    // A wrong expectation is caught.
    assert!(
        contract::registry(
            &reg,
            Hive::LocalMachine,
            r"SYSTEM\Select",
            "Current",
            &RegistryValue::Dword(2),
        )
        .is_err()
    );
}

#[test]
fn registry_key_paths_follow_the_os_rules() {
    let mut reg = MockRegistry::new();
    reg.create_key(Hive::LocalMachine, r"SOFTWARE\Palisade");
    assert!(
        reg.key_exists(Hive::LocalMachine, r"SOFTWARE\Palisade\")
            .unwrap()
    );
    assert!(reg.key_exists(Hive::LocalMachine, "").unwrap());
    for bad in [r"\SOFTWARE", r"SOFTWARE\\Palisade", r"SOFTWARE\\", r"\"] {
        assert_eq!(
            reg.key_exists(Hive::LocalMachine, bad).unwrap_err().kind(),
            ErrorKind::InvalidInput,
            "{bad}"
        );
        assert!(reg.value(Hive::LocalMachine, bad, "x").is_err(), "{bad}");
        assert!(reg.subkeys(Hive::LocalMachine, bad).is_err(), "{bad}");
    }
}

#[test]
fn setting_a_value_again_replaces_it_whatever_the_case() {
    let mut reg = MockRegistry::new();
    reg.set_value(Hive::LocalMachine, "K", "Name", RegistryValue::Dword(1));
    reg.set_value(Hive::LocalMachine, "k", "NAME", RegistryValue::Dword(2));
    assert_eq!(
        reg.value(Hive::LocalMachine, "K", "name").unwrap(),
        Some(RegistryValue::Dword(2))
    );
}

// ---------------------------------------------------------------- events

#[test]
fn recording_sink_captures_and_applies_back_pressure() {
    let mut sink = RecordingSink::with_capacity(2);
    sink.emit("a").unwrap();
    sink.emit("b").unwrap();
    assert_eq!(sink.emit("c").unwrap_err().kind(), ErrorKind::TooLarge);
    assert_eq!(sink.events(), ["a", "b"]);
    assert_eq!(sink.take(), ["a", "b"]);
    sink.emit("c").unwrap();
    let mut unbounded = RecordingSink::new();
    for i in 0..1000 {
        unbounded.emit(i).unwrap();
    }
    assert_eq!(unbounded.events().len(), 1000);
}

// ---------------------------------------------------------------- bundle

/// Generic code over the bundle, as the evaluation path will be.
fn describe<P: Platform>(platform: &P) -> String {
    let env = platform.environment();
    alloc::format!(
        "{} {} {:?} {}",
        env.hostname().unwrap(),
        env.os_version().unwrap(),
        env.architecture(),
        platform.clock().now_utc().unix_secs()
    )
}

#[test]
fn the_mock_platform_works_through_the_generic_bundle() {
    let mut platform = MockPlatform::new();
    platform.clock.set_utc(START);
    platform.environment.hostname = "LAB-07".into();
    assert_eq!(describe(&platform), "LAB-07 10.0.26100.1 X64 1764000000");
    platform
        .fs
        .insert(r"C:\a.txt", MockFile::new(b"hi".to_vec()));
    assert!(platform.file_system().open(r"C:\A.TXT").is_ok());
    assert!(
        platform
            .signatures()
            .embedded(r"C:\a.txt")
            .unwrap()
            .is_empty()
    );
    assert!(platform.identity().current().is_err());
    assert!(platform.processes().by_pid(1).is_err());
    assert!(
        !platform
            .registry()
            .key_exists(Hive::LocalMachine, "X")
            .unwrap()
    );
}

#[test]
fn object_safe_traits_work_as_trait_objects() {
    let clock = MockClock::new(START, MonotonicTime(0));
    let env = MockEnvironment::new();
    let reg = MockRegistry::new();
    let procs = MockProcesses::new();
    let sigs = MockSignatures::new();
    let id = MockIdentity::new();
    let dyn_clock: &dyn Clock = &clock;
    let dyn_env: &dyn Environment = &env;
    let dyn_reg: &dyn Registry = &reg;
    let dyn_procs: &dyn ProcessInfo = &procs;
    let dyn_sigs: &dyn SignatureVerifier = &sigs;
    let dyn_id: &dyn IdentityProvider = &id;
    let mut sink = RecordingSink::<u8>::new();
    let dyn_sink: &mut dyn EventSink<u8> = &mut sink;
    assert_eq!(dyn_clock.now_utc(), START);
    assert_eq!(dyn_env.hostname().unwrap(), "DEV-0001");
    assert!(!dyn_reg.key_exists(Hive::Users, "x").unwrap());
    assert!(dyn_procs.by_pid(1).is_err());
    assert!(dyn_sigs.catalog("x").unwrap().is_none());
    assert!(dyn_id.current().is_err());
    dyn_sink.emit(1).unwrap();
    contract::clock(dyn_clock).unwrap();
    assert!(
        ancestry(
            dyn_procs,
            ProcessKey {
                pid: 1,
                created: START
            }
        )
        .is_err()
    );
}

#[test]
fn platform_errors_display_kind_and_message() {
    let e = PlatformError::new(ErrorKind::AccessDenied, "C:\\x");
    assert_eq!(e.to_string(), "AccessDenied: C:\\x");
    assert_eq!(e.message(), "C:\\x");
    assert_eq!(PlatformError::not_found("k").kind(), ErrorKind::NotFound);
}
