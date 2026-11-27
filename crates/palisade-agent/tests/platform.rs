//! The agent's platform implementations against the shared contracts in
//! `palisade_core::test_util::contract` (#29). The same checks run against
//! the mocks in `palisade-core`, so the two cannot drift. The Windows
//! implementations run here on the Windows CI runners.

// Test code: helpers outside `#[test]` functions may unwrap.
#![allow(clippy::unwrap_used)]

use palisade_agent::platform::{StdEnvironment, StdFileSystem, SystemClock};
use palisade_core::{
    platform::{Clock, Environment, ErrorKind, FileSystem, OpenFile},
    test_util::contract,
};

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "palisade-agent-platform-{tag}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().to_owned()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn system_clock_meets_the_contract() {
    contract::clock(&SystemClock).unwrap();
    let a = SystemClock.monotonic();
    let b = SystemClock.monotonic();
    assert!(b >= a);
}

#[test]
fn std_file_system_meets_the_contract() {
    let dir = TempDir::new("fs");
    let contents: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
    let path = dir.path("sample.bin");
    std::fs::write(&path, &contents).unwrap();
    contract::file_system(&StdFileSystem, &path, &contents, &dir.path("missing.bin")).unwrap();
    contract::file_system(&StdFileSystem, &dir.path("empty"), b"", &dir.path("nope")).unwrap_err();
    std::fs::write(dir.path("empty"), b"").unwrap();
    contract::file_system(&StdFileSystem, &dir.path("empty"), b"", &dir.path("nope")).unwrap();
}

#[test]
fn std_file_system_reports_times_and_rejects_relative_paths_and_directories() {
    let dir = TempDir::new("meta");
    let path = dir.path("a.txt");
    std::fs::write(&path, b"hello").unwrap();
    let file = StdFileSystem.open(&path).unwrap();
    let meta = file.metadata().unwrap();
    assert_eq!(meta.size, 5);
    assert!(!meta.is_dir);
    assert!(meta.modified.is_some());

    let err = StdFileSystem.open("relative.txt").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert_eq!(
        StdFileSystem.owner_sid("relative").unwrap_err().kind(),
        ErrorKind::InvalidInput
    );

    contract::directory(&StdFileSystem, dir.0.to_str().unwrap()).unwrap();
    let mut d = StdFileSystem.open(dir.0.to_str().unwrap()).unwrap();
    assert!(d.metadata().unwrap().is_dir);
    assert_eq!(
        d.read_at(0, &mut [0u8; 4]).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
}

#[test]
fn std_file_system_shares_the_file_with_writers() {
    let dir = TempDir::new("share");
    let path = dir.path("live.log");
    std::fs::write(&path, b"one").unwrap();
    let mut open = StdFileSystem.open(&path).unwrap();
    // Another process may keep writing, and even delete the file, while
    // the agent reads it (on Windows, this needs the share flags).
    std::fs::write(&path, b"one two").unwrap();
    let mut buf = [0u8; 16];
    let n = open.read_at(0, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"one two");
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn windows_only_queries_say_so() {
    let dir = TempDir::new("unsupported");
    let path = dir.path("f");
    std::fs::write(&path, b"x").unwrap();
    assert_eq!(
        StdFileSystem.owner_sid(&path).unwrap_err().kind(),
        ErrorKind::Unsupported
    );
    assert_eq!(
        StdFileSystem.security_descriptor(&path).unwrap_err().kind(),
        ErrorKind::Unsupported
    );
    let streams = StdFileSystem.streams(&path);
    if cfg!(windows) {
        assert_eq!(streams.unwrap_err().kind(), ErrorKind::Unsupported);
    } else {
        assert!(streams.unwrap().is_empty());
    }
    assert_eq!(
        StdFileSystem
            .streams(&dir.path("missing"))
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
}

#[test]
fn std_environment_meets_the_contract() {
    let env = StdEnvironment::from_vars([
        ("COMPUTERNAME".to_owned(), "LAB-01".to_owned()),
        ("ProgramData".to_owned(), r"C:\ProgramData".to_owned()),
        ("PROGRAMDATA".to_owned(), "ignored duplicate".to_owned()),
    ]);
    contract::environment(&env, "ProgramData", r"C:\ProgramData", "PALISADE_UNSET").unwrap();
    assert_eq!(env.hostname().unwrap(), "LAB-01");
    assert_eq!(
        StdEnvironment::from_vars([("HOSTNAME".to_owned(), "box".to_owned())])
            .hostname()
            .unwrap(),
        "box"
    );
    assert_eq!(
        StdEnvironment::from_vars([]).hostname().unwrap_err().kind(),
        ErrorKind::Unsupported
    );
}

#[test]
fn captured_environment_describes_this_machine() {
    let env = StdEnvironment::capture();
    // Windows always reports its host name. Elsewhere (development only) it
    // comes from the environment or /etc/hostname, which may be missing.
    match env.hostname() {
        Ok(name) => assert!(!name.is_empty()),
        #[cfg(windows)]
        Err(e) => panic!("no host name on Windows: {e}"),
        #[cfg(not(windows))]
        Err(e) => assert_eq!(e.kind(), ErrorKind::Unsupported),
    }
    // The addresses exclude loopback.
    for a in env.addresses().unwrap() {
        assert!(!a.addr.is_loopback(), "{a:?}");
    }
    let expected = match std::env::consts::ARCH {
        "x86_64" => palisade_core::platform::Architecture::X64,
        "aarch64" => palisade_core::platform::Architecture::Arm64,
        _ => env.architecture(),
    };
    assert_eq!(env.architecture(), expected);
    if cfg!(windows) {
        let v = env.os_version().unwrap();
        assert_eq!(v.major, 10, "{v}");
        assert!(v.build >= 17763, "{v}");
        env.domain().unwrap();
    } else {
        assert_eq!(env.os_version().unwrap_err().kind(), ErrorKind::Unsupported);
    }
}

/// On NTFS a directory can have named streams; they are data, not
/// directories. The Windows runners exercise this.
#[cfg(windows)]
#[test]
fn a_directory_stream_is_data() {
    let dir = TempDir::new("dirstream");
    let stream = format!("{}:note", dir.0.display());
    std::fs::write(&stream, b"dir stream").unwrap();
    let mut file = StdFileSystem.open(&stream).unwrap();
    let meta = file.metadata().unwrap();
    assert!(!meta.is_dir);
    assert_eq!(meta.size, 10);
    let mut buf = [0u8; 10];
    assert_eq!(file.read_at(0, &mut buf).unwrap(), 10);
    assert_eq!(&buf, b"dir stream");
    contract::directory(&StdFileSystem, dir.0.to_str().unwrap()).unwrap();
}

#[cfg(windows)]
mod windows {
    use palisade_agent::platform::windows::{self, WindowsRegistry};
    use palisade_core::{
        platform::{Hive, Registry, RegistryValue},
        test_util::contract,
    };

    /// Keys and values present on every supported Windows installation.
    const SELECT: &str = r"SYSTEM\Select";
    const ENVIRONMENT: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
    const TIME_ZONE: &str = r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation";
    const GROUP_ORDER: &str = r"SYSTEM\CurrentControlSet\Control\ServiceGroupOrder";
    const MISSING: &str = r"SOFTWARE\Palisade-test-missing";

    #[test]
    fn registry_meets_the_contract() {
        // `Current` names the control set in use, so it equals `Default`
        // except after a last-known-good boot; read it first.
        let current = WindowsRegistry
            .value(Hive::LocalMachine, SELECT, "Current")
            .unwrap()
            .unwrap();
        contract::registry(
            &WindowsRegistry,
            Hive::LocalMachine,
            r"SYSTEM\CurrentControlSet\Control",
            "SystemStartOptions",
            &WindowsRegistry
                .value(
                    Hive::LocalMachine,
                    r"SYSTEM\CurrentControlSet\Control",
                    "SystemStartOptions",
                )
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert!(matches!(current, RegistryValue::Dword(_)));
    }

    #[test]
    fn registry_reads_each_value_type() {
        let reg = WindowsRegistry;
        assert!(reg.key_exists(Hive::LocalMachine, "SOFTWARE").unwrap());
        assert!(reg.key_exists(Hive::LocalMachine, SELECT).unwrap());
        assert!(!reg.key_exists(Hive::LocalMachine, MISSING).unwrap());

        let current = reg.value(Hive::LocalMachine, SELECT, "Current").unwrap();
        assert!(
            matches!(current, Some(RegistryValue::Dword(n)) if n >= 1),
            "{current:?}"
        );

        let comspec = reg
            .value(Hive::LocalMachine, ENVIRONMENT, "ComSpec")
            .unwrap();
        let Some(RegistryValue::ExpandString(comspec)) = comspec else {
            panic!("ComSpec: {comspec:?}");
        };
        assert!(
            comspec.to_ascii_lowercase().ends_with("cmd.exe"),
            "{comspec}"
        );

        let start = reg
            .value(Hive::LocalMachine, TIME_ZONE, "StandardStart")
            .unwrap();
        assert!(
            matches!(&start, Some(RegistryValue::Binary(b)) if b.len() == 16),
            "{start:?}"
        );

        let list = reg.value(Hive::LocalMachine, GROUP_ORDER, "List").unwrap();
        let Some(RegistryValue::MultiString(items)) = list else {
            panic!("List: {list:?}");
        };
        assert!(!items.is_empty() && items.iter().all(|s| !s.is_empty()));

        let host = reg
            .value(
                Hive::LocalMachine,
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                "Hostname",
            )
            .unwrap();
        assert!(matches!(host, Some(RegistryValue::String(_))), "{host:?}");

        assert_eq!(
            reg.value(Hive::LocalMachine, SELECT, "Palisade-missing")
                .unwrap(),
            None
        );
        assert_eq!(reg.value(Hive::LocalMachine, MISSING, "x").unwrap(), None);
    }

    #[test]
    fn registry_lists_subkeys_and_user_hives() {
        let reg = WindowsRegistry;
        let control = reg
            .subkeys(Hive::LocalMachine, r"SYSTEM\CurrentControlSet\Control")
            .unwrap();
        assert!(
            control
                .iter()
                .any(|k| k.eq_ignore_ascii_case("TimeZoneInformation")),
            "{control:?}"
        );
        // HKEY_USERS always holds the LocalSystem profile, S-1-5-18.
        let users = reg.subkeys(Hive::Users, "").unwrap();
        assert!(users.iter().any(|k| k == "S-1-5-18"), "{users:?}");
        assert!(reg.subkeys(Hive::LocalMachine, MISSING).is_err());
    }

    #[test]
    fn host_name_matches_the_environment() {
        let name = windows::hostname().unwrap();
        let env = std::env::var("COMPUTERNAME").unwrap();
        // COMPUTERNAME is the upper-case NetBIOS form of the same name,
        // at most 15 characters.
        let netbios: String = name.to_uppercase().chars().take(15).collect();
        assert_eq!(netbios, env.to_uppercase());
    }

    // ------------------------------------------------------------------
    // Processes and identity, against this test process and its token.
    // ------------------------------------------------------------------

    use palisade_agent::platform::SystemClock;
    use palisade_agent::platform::windows::{WindowsIdentity, WindowsProcesses};
    use palisade_core::platform::{
        Clock, DirectoryGroups, Elevation, ErrorKind, IdentityProvider, IntegrityLevel,
        ProcessInfo, ProcessKey, SessionKind, UtcTime, ancestry,
    };

    /// `BUILTIN\Administrators` and `BUILTIN\Users`.
    const ADMINISTRATORS: &str = "S-1-5-32-544";
    const USERS: &str = "S-1-5-32-545";
    /// `NT AUTHORITY\INTERACTIVE`, which `BUILTIN\Users` always holds.
    const INTERACTIVE: &str = "S-1-5-4";

    fn me() -> ProcessKey {
        WindowsProcesses.by_pid(std::process::id()).unwrap().key
    }

    #[test]
    fn processes_meet_the_contract() {
        contract::processes(&WindowsProcesses, me()).unwrap();
    }

    #[test]
    fn this_process_is_described_and_its_ancestry_ends() {
        let record = WindowsProcesses.by_pid(std::process::id()).unwrap();
        let exe = std::env::current_exe().unwrap();
        assert_eq!(
            std::fs::canonicalize(&record.image_path).unwrap(),
            std::fs::canonicalize(&exe).unwrap()
        );
        let line = record.command_line.as_deref().unwrap();
        let name = exe.file_stem().unwrap().to_str().unwrap();
        assert!(line.contains(name), "{line}");
        assert!(record.parent_pid.is_some());
        // Created in the past, and after 2020.
        assert!(record.key.created < SystemClock.now_utc());
        assert!(record.key.created > UtcTime(1_577_836_800_000_000));

        // The test runner started this process, so the chain has at least
        // the parent, and it ends: bounded, without loops, each ancestor
        // no newer than its child.
        let chain = ancestry(&WindowsProcesses, record.key).unwrap();
        assert!(!chain.is_empty());
        assert!(chain.len() < palisade_core::platform::MAX_ANCESTRY);
        assert_eq!(Some(chain[0].key.pid), record.parent_pid);
        let mut child = &record;
        for parent in &chain {
            assert!(parent.key.created <= child.key.created);
            assert_ne!(parent.key, record.key);
            child = parent;
        }
    }

    #[test]
    fn a_process_that_exited_is_not_found() {
        // A child that stays alive until it is killed, so it is always
        // found first.
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/c", "ping -n 60 127.0.0.1 >NUL"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let key = WindowsProcesses.by_pid(pid).unwrap().key;
        assert_eq!(WindowsProcesses.get(key).unwrap().key, key);
        WindowsIdentity::new().token(key).unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        // Gone, even though `child` still holds a handle to it (which
        // also keeps its ID from being reused).
        for e in [
            WindowsProcesses.by_pid(pid).unwrap_err(),
            WindowsProcesses.get(key).unwrap_err(),
            WindowsIdentity::new().token(key).unwrap_err(),
        ] {
            assert_eq!(e.kind(), ErrorKind::NotFound, "{e}");
        }
        drop(child);
        // Process IDs are multiples of 4, so this one never exists.
        assert_eq!(
            WindowsProcesses.by_pid(0xFFFF_FFF1).unwrap_err().kind(),
            ErrorKind::NotFound
        );
    }

    #[test]
    fn the_system_process_is_described() {
        // PID 4 is the System process, the root of every chain: it has no
        // parent. The OS may refuse some of its fields (it has no image
        // file), and the backend then fails rather than guess; but it is
        // running, so it is never `NotFound`.
        match WindowsProcesses.by_pid(4) {
            Ok(system) => {
                assert_eq!(system.key.pid, 4);
                assert_eq!(system.parent_pid, None);
                assert!(ancestry(&WindowsProcesses, system.key).unwrap().is_empty());
            }
            Err(e) => assert_ne!(e.kind(), ErrorKind::NotFound, "{e}"),
        }
    }

    #[test]
    fn identity_meets_the_contract() {
        contract::identity(&WindowsIdentity::new(), me(), USERS, INTERACTIVE).unwrap();
    }

    #[test]
    fn this_token_is_described() {
        let id = WindowsIdentity::new();
        let current = id.current().unwrap();
        assert_eq!(id.token(me()).unwrap(), current);
        // Everyone (S-1-1-0) is in every token but anonymous ones.
        assert!(current.groups.iter().any(|g| g.sid == "S-1-1-0"));
        assert!(current.integrity >= IntegrityLevel::Medium);
        if current.session_id == 0 {
            assert_eq!(current.session_kind, SessionKind::Services);
        } else {
            assert_ne!(current.session_kind, SessionKind::Services);
        }
        // The CI runners run tests as an administrator. An elevated token
        // has the administrators group enabled; a filtered one (UAC's
        // limited half) has it deny-only.
        let admins = current.groups.iter().find(|g| g.sid == ADMINISTRATORS);
        if current.elevated {
            assert!(current.integrity >= IntegrityLevel::High);
            if let Some(admins) = admins {
                assert!(!admins.deny_only, "{current:?}");
            }
        }
        if current.elevation == Elevation::Limited {
            assert!(admins.is_none_or(|g| g.deny_only), "{current:?}");
        }

        let name = id.account_name(&current.user_sid).unwrap().unwrap();
        assert!(!name.name.is_empty());
        let system = id.account_name("S-1-5-18").unwrap().unwrap();
        assert!(system.domain.is_some(), "{system:?}");
        // A well-formed SID no account has.
        assert_eq!(id.account_name("S-1-5-21-1-2-3-999999").unwrap(), None);
    }

    #[test]
    fn local_groups_are_listed_by_sid_only() {
        let id = WindowsIdentity::new();
        let admins = id.local_group_members(ADMINISTRATORS).unwrap();
        assert!(!admins.is_empty());
        assert!(admins.iter().all(|m| m.starts_with("S-1-")));
        // A user, a well-known group that is not a local group, and an
        // unknown SID are not local groups.
        let me = id.current().unwrap().user_sid;
        for sid in [me.as_str(), "S-1-1-0", "S-1-5-21-1-2-3-999999"] {
            assert_eq!(
                id.local_group_members(sid).unwrap_err().kind(),
                ErrorKind::NotFound,
                "{sid}"
            );
        }
        assert_eq!(
            id.local_group_members("Administrators").unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn directory_groups_come_from_the_cache() {
        let id = WindowsIdentity::new();
        let user = "S-1-12-1-1-2-3-4";
        assert_eq!(id.directory_groups(user).unwrap(), None);
        let groups = DirectoryGroups {
            groups: vec!["0f1e2d3c-0000-4000-8000-000000000001".into()],
            fetched_at: UtcTime(1_764_000_000_000_000),
        };
        id.cache_directory_groups(user, groups.clone()).unwrap();
        assert_eq!(
            id.directory_groups("s-1-12-1-1-2-3-4").unwrap(),
            Some(groups)
        );
        assert_eq!(
            id.directory_groups("alice").unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        assert!(
            id.cache_directory_groups(
                "alice",
                DirectoryGroups {
                    groups: vec![],
                    fetched_at: UtcTime(0),
                }
            )
            .is_err()
        );
    }

    // ------------------------------------------------------------------
    // The file-system context, through `palisade_fileid::win`.
    // ------------------------------------------------------------------

    use palisade_agent::platform::windows::WindowsFileSystem;
    use palisade_core::platform::{FileSystem, OpenFile};

    #[test]
    fn file_system_meets_the_contract() {
        let dir = super::TempDir::new("winfs");
        let contents: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let path = dir.path("sample.bin");
        std::fs::write(&path, &contents).unwrap();
        contract::file_system(&WindowsFileSystem, &path, &contents, &dir.path("missing")).unwrap();
        contract::directory(&WindowsFileSystem, dir.0.to_str().unwrap()).unwrap();
    }

    #[test]
    fn file_ids_and_usns_come_from_the_handle() {
        let dir = super::TempDir::new("winfs-ids");
        let a = dir.path("a.bin");
        let b = dir.path("b.bin");
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        let ma = WindowsFileSystem.open(&a).unwrap().metadata().unwrap();
        let mb = WindowsFileSystem.open(&b).unwrap().metadata().unwrap();
        // The temporary folder on the CI runners is on the NTFS system
        // volume, which has file IDs and an active change journal.
        assert!(ma.file_id.is_some() && ma.volume_serial.is_some(), "{ma:?}");
        assert_ne!(ma.file_id, mb.file_id);
        assert_eq!(ma.volume_serial, mb.volume_serial);
        assert!(ma.usn.is_some_and(|u| u >= 0), "{ma:?}");
        // A hard link is the same file: same ID.
        let link = dir.path("link.bin");
        std::fs::hard_link(&a, &link).unwrap();
        let ml = WindowsFileSystem.open(&link).unwrap().metadata().unwrap();
        assert_eq!(ml.file_id, ma.file_id);
    }

    #[test]
    fn owners_and_descriptors() {
        let dir = super::TempDir::new("winfs-owner");
        let path = dir.path("mine.txt");
        std::fs::write(&path, b"x").unwrap();
        let sd = WindowsFileSystem
            .security_descriptor(&path)
            .unwrap()
            .unwrap();
        let parsed = palisade_fileid::fsctx::SecurityDescriptor::from_self_relative(&sd).unwrap();
        let recorded = parsed.owner.map(|s| s.to_string()).unwrap();
        let me = WindowsIdentity::new().current().unwrap();
        // This process's user, or Administrators for an elevated one.
        assert!(
            recorded == me.user_sid || recorded == ADMINISTRATORS,
            "{recorded} vs {}",
            me.user_sid
        );
        // The owner is reported only where the volume says owners can be
        // relied on (a physical local NTFS or ReFS disk); elsewhere, such
        // as a runner whose disk reports a virtual bus, it is `None`,
        // never a guess.
        let file = std::fs::File::open(&path).unwrap();
        let trusted_volume = palisade_fileid::win::volume::read_volume(&file).supports_owner();
        let owner = WindowsFileSystem.owner_sid(&path).unwrap();
        if trusted_volume {
            assert_eq!(owner.as_deref(), Some(recorded.as_str()));
        } else {
            assert_eq!(owner, None);
        }

        let missing = dir.path("missing.txt");
        assert_eq!(
            WindowsFileSystem.owner_sid(&missing).unwrap_err().kind(),
            ErrorKind::NotFound
        );
        assert_eq!(
            WindowsFileSystem
                .security_descriptor("relative.txt")
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn alternate_data_streams_are_listed() {
        let dir = super::TempDir::new("winfs-ads");
        let path = dir.path("download.exe");
        std::fs::write(&path, b"MZ").unwrap();
        assert!(WindowsFileSystem.streams(&path).unwrap().is_empty());
        std::fs::write(
            format!("{path}:Zone.Identifier"),
            b"[ZoneTransfer]\r\nZoneId=3\r\n",
        )
        .unwrap();
        std::fs::write(format!("{path}:extra"), b"12345").unwrap();
        let mut streams = WindowsFileSystem.streams(&path).unwrap();
        streams.sort_by(|a, b| a.name.cmp(&b.name));
        let names: Vec<(&str, u64)> = streams.iter().map(|s| (s.name.as_str(), s.size)).collect();
        assert_eq!(names, [("Zone.Identifier", 26), ("extra", 5)]);
        // A stream is data, readable through `open`.
        let mut f = WindowsFileSystem.open(&format!("{path}:extra")).unwrap();
        let mut buf = [0_u8; 8];
        assert_eq!(f.read_at(0, &mut buf).unwrap(), 5);
        assert_eq!(
            WindowsFileSystem
                .streams(&dir.path("missing"))
                .unwrap_err()
                .kind(),
            ErrorKind::NotFound
        );
    }
}
