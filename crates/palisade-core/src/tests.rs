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

mod path {
    use alloc::string::String;
    use alloc::vec::Vec;

    use proptest::prelude::*;

    use crate::path::{PathKind, VolumeMap, normalize, normalize_with};

    #[test]
    fn normalisation_vectors() {
        let mut volumes = VolumeMap::new();
        assert!(volumes.insert("\\Device\\HarddiskVolume3", 'c'));
        for (input, expected, kind) in [
            // Separators, `.` and `..`.
            (
                "C:/Windows/System32",
                "C:\\Windows\\System32",
                PathKind::Drive,
            ),
            ("c:\\\\a\\\\\\b\\", "C:\\a\\b", PathKind::Drive),
            ("C:\\a\\.\\b\\..\\c", "C:\\a\\c", PathKind::Drive),
            ("C:\\..\\..\\x", "C:\\x", PathKind::Drive),
            ("C:", "C:", PathKind::Relative),
            ("C:\\", "C:\\", PathKind::Drive),
            // Prefixes.
            (
                "\\\\?\\C:\\Tools\\a.exe",
                "C:\\Tools\\a.exe",
                PathKind::Drive,
            ),
            (
                "\\??\\C:\\Tools\\a.exe",
                "C:\\Tools\\a.exe",
                PathKind::Drive,
            ),
            ("\\\\.\\C:\\Tools", "C:\\Tools", PathKind::Drive),
            (
                "\\\\?\\UNC\\srv\\share\\a",
                "\\\\srv\\share\\a",
                PathKind::Unc,
            ),
            (
                "\\\\?\\unc\\srv\\share\\a",
                "\\\\srv\\share\\a",
                PathKind::Unc,
            ),
            // UNC.
            ("//srv/share/x/../y", "\\\\srv\\share\\y", PathKind::Unc),
            ("\\\\\\srv\\share", "\\\\srv\\share", PathKind::Unc),
            (
                "\\\\srv\\share\\..\\..\\x",
                "\\\\srv\\share\\x",
                PathKind::Unc,
            ),
            // Device paths.
            (
                "\\Device\\HarddiskVolume3\\Windows\\a.exe",
                "C:\\Windows\\a.exe",
                PathKind::Drive,
            ),
            (
                "\\\\?\\GLOBALROOT\\Device\\HarddiskVolume3\\x",
                "C:\\x",
                PathKind::Drive,
            ),
            (
                "\\Device\\HarddiskVolume33\\x",
                "\\Device\\HarddiskVolume33\\x",
                PathKind::Device,
            ),
            (
                "\\\\?\\Volume{0a1b}\\x",
                "\\\\?\\Volume{0a1b}\\x",
                PathKind::Device,
            ),
            ("\\\\.\\..\\x", "\\\\?\\..\\x", PathKind::Device),
            ("\\\\..\\x", "\\\\?\\UNC\\..\\x", PathKind::Device),
            ("\\\\srv\\..\\x", "\\\\?\\UNC\\srv\\..\\x", PathKind::Device),
            ("\\\\srv\\.", "\\\\?\\UNC\\srv\\.", PathKind::Device),
            ("C:\\a\\b::$DATA\\.", "C:\\a\\b", PathKind::Drive),
            // Spellings that only show once another rule has run.
            (
                "C:\\a.txt::$INDEX_ALLOCATION::$DATA",
                "C:\\a.txt",
                PathKind::Drive,
            ),
            (
                "C:\\a\\..::$INDEX_ALLOCATION::$DATA",
                "C:\\",
                PathKind::Drive,
            ),
            (
                "\\\\?\\GLOBALROOT\\a\\..\\Device\\HarddiskVolume3\\x",
                "C:\\x",
                PathKind::Drive,
            ),
            (
                "\\\\?\\GLOBALROOT\\.\\Device\\HarddiskVolume3\\x",
                "C:\\x",
                PathKind::Drive,
            ),
            (
                "\\\\?\\GLOBALROOT\\Device::$INDEX_ALLOCATION\\HarddiskVolume3\\x",
                "C:\\x",
                PathKind::Drive,
            ),
            // A relative path never becomes an absolute one.
            (
                "\\Device::$INDEX_ALLOCATION\\HarddiskVolume3\\x",
                "\\.\\Device\\HarddiskVolume3\\x",
                PathKind::Relative,
            ),
            (
                "\\??::$INDEX_ALLOCATION\\C:\\x",
                "\\.\\??\\C:\\x",
                PathKind::Relative,
            ),
            (
                "\\::$INDEX_ALLOCATION\\srv\\share\\evil.exe",
                "\\srv\\share\\evil.exe",
                PathKind::Relative,
            ),
            (
                "\\::$INDEX_ALLOCATION\\?\\C:\\Windows\\cmd.exe",
                "\\?\\C:\\Windows\\cmd.exe",
                PathKind::Relative,
            ),
            (
                "\\::$INDEX_ALLOCATION\\.\\C:\\Windows\\cmd.exe",
                "\\.\\C:\\Windows\\cmd.exe",
                PathKind::Relative,
            ),
            (
                "\\:$I30:$INDEX_ALLOCATION\\Device\\HarddiskVolume3\\x",
                "\\.\\Device\\HarddiskVolume3\\x",
                PathKind::Relative,
            ),
            // Streams and stream types.
            ("C:\\a.txt::$DATA", "C:\\a.txt", PathKind::Drive),
            ("C:\\a.txt:s:$DATA", "C:\\a.txt:s", PathKind::Drive),
            ("C:\\a.txt:s", "C:\\a.txt:s", PathKind::Drive),
            (
                "C:\\dir::$INDEX_ALLOCATION\\a",
                "C:\\dir\\a",
                PathKind::Drive,
            ),
            (
                "C:\\dir:$I30:$INDEX_ALLOCATION\\a",
                "C:\\dir\\a",
                PathKind::Drive,
            ),
            // Trailing dots and spaces are significant.
            ("C:\\a.exe.", "C:\\a.exe.", PathKind::Drive),
            ("C:\\a.exe ", "C:\\a.exe ", PathKind::Drive),
            // Case is kept, except for the drive letter.
            ("d:\\MiXeD", "D:\\MiXeD", PathKind::Drive),
            // Relative forms.
            ("a\\.\\..\\b", "a\\.\\..\\b", PathKind::Relative),
            ("::$INDEX_ALLOCATION\\a:b", ".\\a:b", PathKind::Relative),
            ("\\Windows", "\\Windows", PathKind::Relative),
            ("c:a", "C:a", PathKind::Relative),
            ("**\\cmd.exe", "**\\cmd.exe", PathKind::Relative),
        ] {
            let p = normalize_with(input, &volumes);
            assert_eq!(p.as_str(), expected, "{input:?}");
            assert_eq!(p.kind(), kind, "{input:?}");
        }
    }

    #[test]
    fn long_stream_type_chains_collapse() {
        let chain = "::$INDEX_ALLOCATION::$DATA".repeat(40);
        let p = normalize(&format!("C:\\a.txt{chain}"));
        assert_eq!(p.as_str(), "C:\\a.txt");
        assert_eq!(p.stream(), None);
        let p = normalize(&format!("C:\\a\\..{chain}"));
        assert_eq!(p.as_str(), "C:\\");
        let p = normalize(&format!("C:\\a.txt:s{}", ":$DATA".repeat(3)));
        assert_eq!(p.as_str(), "C:\\a.txt:s");
        assert_eq!(p.stream(), Some("s"));
        assert_eq!(normalize(p.as_str()), p);
    }

    #[test]
    fn components_and_streams() {
        let p = normalize("C:\\Tools\\App\\run.tar.gz:payload");
        assert_eq!(p.root(), "C:\\");
        assert_eq!(p.directory(), Some("C:\\Tools\\App"));
        assert_eq!(p.file_name(), Some("run.tar.gz"));
        assert_eq!(p.extension(), Some("gz"));
        assert_eq!(p.stream(), Some("payload"));
        assert_eq!(p.without_stream(), "C:\\Tools\\App\\run.tar.gz");

        let top = normalize("C:\\a.exe");
        assert_eq!(top.directory(), Some("C:\\"));
        assert_eq!(top.stream(), None);
        let unc = normalize("\\\\srv\\share\\a.exe");
        assert_eq!(unc.root(), "\\\\srv\\share");
        assert_eq!(unc.directory(), Some("\\\\srv\\share"));
        assert_eq!(normalize("C:\\").directory(), None);
        assert_eq!(normalize("C:\\").file_name(), None);
        assert_eq!(normalize("C:\\noext").extension(), None);
        assert_eq!(normalize("C:\\dot.").extension(), None);
    }

    #[test]
    fn streams_on_roots_and_directories() {
        let mut volumes = VolumeMap::new();
        volumes.insert("\\Device\\HarddiskVolume3", 'C');
        for raw in ["C:\\:payload", "\\Device\\HarddiskVolume3\\:payload"] {
            let p = normalize_with(raw, &volumes);
            assert_eq!(p.as_str(), "C:\\:payload", "{raw}");
            assert_eq!(p.stream(), Some("payload"));
            assert_eq!(p.without_stream(), "C:\\");
            assert_eq!(p.file_name(), None);
            assert_eq!(p.directory(), None);
        }
        let unc = normalize("\\\\srv\\share\\:payload");
        assert_eq!(unc.stream(), Some("payload"));
        assert_eq!(unc.without_stream(), "\\\\srv\\share");
        assert_eq!(unc.file_name(), None);
        assert_eq!(unc.directory(), None);
        // A stream on a directory belongs to the directory.
        let dir = normalize("C:\\dir\\:payload");
        assert_eq!(dir.without_stream(), "C:\\dir");
        assert_eq!(dir.file_name(), Some("dir"));
        assert_eq!(dir.directory(), Some("C:\\"));
        assert_eq!(normalize(dir.as_str()), dir);
    }

    #[test]
    fn volume_map_rejects_bad_entries() {
        let mut volumes = VolumeMap::new();
        assert!(!volumes.insert("\\Device\\", 'c'));
        assert!(!volumes.insert("C:\\", 'c'));
        assert!(!volumes.insert("\\Device\\HarddiskVolume1", '1'));
        assert!(volumes.insert("/Device/HarddiskVolume1/", 'e'));
        assert_eq!(
            normalize_with("\\Device\\harddiskvolume1\\x", &volumes).as_str(),
            "E:\\x"
        );
    }

    fn segment() -> impl Strategy<Value = String> {
        prop_oneof![
            Just(String::from(".")),
            Just(String::from("..")),
            Just(String::new()),
            Just(String::from("a.txt:s")),
            Just(String::from("a::$DATA")),
            Just(String::from("d:$I30:$INDEX_ALLOCATION")),
            Just(String::from("Device")),
            Just(String::from("HarddiskVolume3")),
            Just(String::from("GLOBALROOT")),
            Just(String::from("??")),
            Just(String::from("C:")),
            Just(String::from("UNC")),
            Just(String::from("..::$INDEX_ALLOCATION")),
            Just(String::from("x::$INDEX_ALLOCATION::$DATA")),
            Just(String::from("::$INDEX_ALLOCATION")),
            Just(String::from(":$I30:$INDEX_ALLOCATION")),
            Just(String::from("?")),
            "x(::\\$INDEX_ALLOCATION::\\$DATA){1,20}",
            "[A-Za-z0-9 ._$:?-]{1,8}",
        ]
    }

    fn raw_path() -> impl Strategy<Value = String> {
        (
            prop_oneof![
                Just(""),
                Just("C:"),
                Just("c:\\"),
                Just("\\"),
                Just("\\\\"),
                Just("\\\\?\\"),
                Just("\\??\\"),
                Just("\\\\.\\"),
                Just("\\\\?\\UNC\\"),
                Just("\\Device\\HarddiskVolume3"),
                Just("\\\\?\\GLOBALROOT\\Device\\HarddiskVolume3"),
                Just("\\\\?\\GLOBALROOT\\"),
                Just("\\::$INDEX_ALLOCATION\\"),
                Just("\\??::$INDEX_ALLOCATION\\"),
            ],
            proptest::collection::vec(segment(), 0..6),
            prop_oneof![Just("\\"), Just("/"), Just("\\\\")],
        )
            .prop_map(|(prefix, parts, sep)| {
                let mut s = String::from(prefix);
                s.push_str(&parts.join(sep));
                s
            })
    }

    proptest! {
        #[test]
        fn normalisation_is_idempotent(raw in raw_path()) {
            let mut volumes = VolumeMap::new();
            volumes.insert("\\Device\\HarddiskVolume3", 'C');
            let once = normalize_with(&raw, &volumes);
            let twice = normalize_with(once.as_str(), &volumes);
            // Only an input that starts like an absolute path can become
            // one.
            let flat = raw.replace('/', "\\");
            let b = flat.as_bytes();
            let absolute_start = flat.starts_with("\\\\")
                || flat.starts_with("\\??\\")
                || flat.get(..8).is_some_and(|h| h.eq_ignore_ascii_case("\\Device\\"))
                || (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\');
            if !absolute_start {
                prop_assert_eq!(once.kind(), PathKind::Relative, "{:?} gave {}", raw, once);
            }
            prop_assert_eq!(once.as_str(), twice.as_str());
            prop_assert_eq!(once.kind(), twice.kind());
            // No `.` or `..` component survives in an absolute path, and no
            // separator is doubled after the root.
            if once.is_resolved() {
                let body = &once.as_str()[once.root().len()..];
                let parts: Vec<&str> = body.split('\\').filter(|p| !p.is_empty()).collect();
                prop_assert!(parts.iter().all(|p| *p != "." && *p != ".."), "{}", once);
                prop_assert!(!body.contains("\\\\"), "{}", once);
            }
        }
    }
}

mod verification {
    use alloc::string::ToString;

    use crate::VerificationError;

    #[test]
    fn os_codes_match_the_os_table() {
        // The OS code integrity `VerificationError` values, 0 to 28, in
        // order. #58 decodes OS events with this table, so it must not
        // drift.
        let os = [
            "ok",
            "invalid_hash",
            "shared_writable_sections",
            "not_signed",
            "revoked",
            "expired",
            "weak_hash_algorithm",
            "untrusted_root",
            "generic",
            "signing_time_untrusted",
            "page_hashes_required",
            "page_hash_mismatch",
            "not_valid_for_protected_process_light",
            "not_valid_for_protected_process",
            "missing_arm_eku",
            "certified_driver_check_failed",
            "default_policy_signing_level_not_met",
            "custom_policy_signing_level_not_met",
            "custom_signers_not_met",
            "revoked_by_hash",
            "sha1_timestamp_past_cutoff",
            "policy_failed",
            "not_isolated_user_mode_signed",
            "unsupported_key_algorithm",
            "pre_release_root_not_allowed",
            "anti_cheat_policy_violation",
            "explicitly_denied",
            "chain_tampered",
            "resource_page_hash_mismatch",
        ];
        for (code, name) in (0_u16..).zip(os) {
            let e = VerificationError::from_code(code).unwrap();
            assert_eq!(e.as_str(), name);
            assert!(e.is_os_code());
        }
        assert_eq!(VerificationError::from_code(29), None);
        assert_eq!(VerificationError::from_code(999), None);
    }

    #[test]
    fn palisade_codes_start_at_1000() {
        let own = [
            (1000, VerificationError::DigestMismatch),
            (1001, VerificationError::MalformedSignature),
            (1002, VerificationError::ChainIncomplete),
            (1003, VerificationError::MissingRequiredEku),
            (1004, VerificationError::KeyTooSmall),
            (1005, VerificationError::CountersignatureRequired),
            (1006, VerificationError::RevocationUnavailable),
        ];
        for (code, e) in own {
            assert_eq!(e.code(), code);
            assert!(!e.is_os_code());
            assert_eq!(VerificationError::from_code(code), Some(e));
        }
        assert_eq!(VerificationError::from_code(1007), None);
    }

    #[test]
    fn codes_and_names_are_unique_and_round_trip() {
        let all = VerificationError::ALL;
        for (i, a) in all.iter().enumerate() {
            assert_eq!(a.to_string().parse::<VerificationError>(), Ok(*a));
            for b in &all[i + 1..] {
                assert_ne!(a.code(), b.code());
                assert_ne!(a.as_str(), b.as_str());
            }
        }
        // `ALL` is in numeric order.
        assert!(all.windows(2).all(|w| w[0].code() < w[1].code()));
        assert!(VerificationError::Ok.is_ok());
        assert!("Expired".parse::<VerificationError>().is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_uses_the_name() {
        assert_eq!(
            serde_json::to_string(&VerificationError::Sha1TimestampPastCutoff).unwrap(),
            "\"sha1_timestamp_past_cutoff\""
        );
        assert_eq!(
            serde_json::from_str::<VerificationError>("\"revoked_by_hash\"").unwrap(),
            VerificationError::RevokedByHash
        );
    }
}
