//! Probed context (#329).

use super::*;
use crate::model::Operator;

#[test]
fn targets_have_one_canonical_form() {
    for (field, raw, canonical) in [
        (Field::EnvVar, "Path", "PATH"),
        (
            Field::RegKey,
            r"HKEY_LOCAL_MACHINE\Software\Vendor",
            r"HKLM\software\vendor",
        ),
        (Field::RegKey, r"hklm\SOFTWARE", r"HKLM\software"),
        (Field::RegValue, "HKCU", "HKCU"),
        (Field::RegKey, r"HKEY_USERS\S-1-5-18", r"HKU\s-1-5-18"),
        (Field::RegKey, r"HKEY_CLASSES_ROOT\.exe", r"HKCR\.exe"),
        (Field::FsFile, r"C:/Tools/Flag.TXT", r"C:\TOOLS\FLAG.TXT"),
        (
            Field::FsFolder,
            r"\\server\share\dir",
            r"\\SERVER\SHARE\DIR",
        ),
    ] {
        assert_eq!(
            canonical_target(field, raw).as_deref(),
            Ok(canonical),
            "{raw}"
        );
    }
    for (field, raw) in [
        (Field::EnvVar, ""),
        (Field::EnvVar, "A=B"),
        (Field::EnvVar, "A\u{7}"),
        (Field::RegKey, r"HKLM\\Software"),
        (Field::RegKey, r"Software\Vendor"),
        (Field::RegKey, "HKLM\\a\u{1}"),
        (Field::FsFile, "relative.txt"),
        (Field::FsFile, r"C:\Tools\*.txt"),
        (Field::FsFile, r"%TEMP%\x"),
        (Field::FsFile, r"C:\x.txt:stream"),
        (Field::UserSid, "x"),
    ] {
        assert!(canonical_target(field, raw).is_err(), "{field:?} {raw:?}");
    }
    let long = "A".repeat(crate::model::limits::MAX_VALUE_BYTES + 1);
    assert!(canonical_target(Field::FsFile, &long).is_err());
    assert!(canonical_target(Field::EnvVar, &"A".repeat(256)).is_err());
}

#[test]
fn the_table_is_keyed_by_canonical_target() {
    let mut probes = Probes::default();
    assert!(probes.is_empty());
    assert!(probes.insert(
        Field::RegValue,
        r"HKEY_LOCAL_MACHINE\Software\X",
        Some("Enabled"),
        Probe::Number(1)
    ));
    assert!(!probes.insert(Field::UserSid, "x", None, Probe::Present));
    assert!(!probes.insert(Field::FsFile, "relative", None, Probe::Present));
    assert_eq!(
        probes.get(Field::RegValue, r"hklm\SOFTWARE\x", Some("enabled")),
        Some(&Probe::Number(1))
    );
    // Another value name, or the default value, is another probe.
    assert_eq!(probes.get(Field::RegValue, r"HKLM\Software\X", None), None);
    // `value_name` only means something on `reg.value`.
    let probes = Probes::EMPTY.with(Field::EnvVar, "path", Some("ignored"), Probe::Absent);
    assert_eq!(
        probes.get(Field::EnvVar, "PATH", None),
        Some(&Probe::Absent)
    );
    assert_eq!(probes.iter().count(), 1);
    assert_eq!(probe_key(Field::UserSid, "x", None), None);
}

#[test]
fn probe_targets_lists_each_target_once() {
    let c = |field, target: &str| {
        Match::Criterion(Criterion::probe(
            field,
            Operator::Exists,
            target,
            Vec::<String>::new(),
        ))
    };
    let cold = |target: &str, cadence| {
        Match::Criterion(Criterion {
            evaluate: Some(cadence),
            ..Criterion::probe(
                Field::FsFile,
                Operator::Exists,
                target,
                Vec::<String>::new(),
            )
        })
    };
    let tree = Match::All(vec![
        c(Field::RegKey, r"HKLM\Software\A"),
        Match::Not(Box::new(c(Field::RegKey, r"hklm\software\a"))),
        // One file with two cadences: the more frequent one is kept.
        cold(r"C:\flag", crate::model::Cadence::OnPolicyChange),
        cold(r"c:\FLAG", crate::model::Cadence::OncePerSession),
        cold(r"C:\flag", crate::model::Cadence::OncePerBoot),
        c(Field::FsFile, "not a path"),
        Match::Criterion(Criterion::new(
            Field::UserSid,
            Operator::Equals,
            ["S-1-5-18"],
        )),
    ]);
    let targets = probe_targets([&tree]);
    assert_eq!(
        targets,
        [
            ProbeTarget {
                field: Field::RegKey,
                target: r"HKLM\software\a".to_owned(),
                value_name: None,
                cost: crate::model::CostClass::Warm,
                cadence: None,
            },
            ProbeTarget {
                field: Field::FsFile,
                target: r"C:\FLAG".to_owned(),
                value_name: None,
                cost: crate::model::CostClass::Cold,
                cadence: Some(crate::model::Cadence::OncePerSession),
            },
        ]
    );
}

#[test]
fn only_the_machine_hive_is_not_user_controlled() {
    let c = |field, target: Option<&str>| Criterion {
        target: target.map(str::to_owned),
        ..Criterion::new(field, Operator::Exists, Vec::<String>::new())
    };
    for (field, target, user) in [
        (Field::EnvVar, Some("PATH"), true),
        (Field::FsFile, Some(r"C:\Windows\x"), true),
        (Field::FsFolder, Some(r"C:\Windows"), true),
        (Field::RegKey, Some(r"HKLM\Software"), false),
        (Field::RegValue, Some(r"HKEY_LOCAL_MACHINE\Software"), false),
        (Field::RegKey, Some(r"HKCU\Software"), true),
        (Field::RegKey, Some(r"HKU\S-1-5-18"), true),
        (Field::RegKey, Some(r"HKCR\.exe"), true),
        (Field::RegKey, Some(r"Bogus\x"), true),
        (Field::RegKey, None, true),
        (Field::UserSid, None, false),
    ] {
        assert_eq!(
            is_user_controlled(&c(field, target)),
            user,
            "{field:?} {target:?}"
        );
    }
}
