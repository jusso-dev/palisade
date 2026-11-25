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
}
