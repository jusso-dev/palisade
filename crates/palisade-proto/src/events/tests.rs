// Tests may index: a panic is a test failure.
#![allow(clippy::indexing_slicing)]
use proptest::prelude::*;

use super::arbitrary;
use super::*;

const UUID: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f";

/// The smallest valid event.
fn minimal_json() -> serde_json::Value {
    serde_json::json!({
        "schema_version": "1.0.0",
        "event_id": UUID,
        "event_type": "agent.started",
        "category": "agent",
        "action": "start",
        "outcome": "info",
        "severity": 2,
        "description": "The agent started.",
        "ts": "2026-11-24T03:15:22.123456Z",
        "clock_synced": true,
        "tenant_id": UUID,
        "host": { "id": UUID },
        "seq": 0
    })
}

fn minimal() -> Event {
    serde_json::from_value(minimal_json()).unwrap()
}

fn with(patch: serde_json::Value) -> serde_json::Value {
    let mut value = minimal_json();
    for (k, v) in patch.as_object().unwrap() {
        if v.is_null() {
            value.as_object_mut().unwrap().remove(k);
        } else {
            value[k] = v.clone();
        }
    }
    value
}

// ---------------------------------------------------------------- values

#[test]
fn timestamps_have_one_spelling() {
    let t: Timestamp = "2026-11-24T03:15:22.123456Z".parse().unwrap();
    assert_eq!(t.to_string(), "2026-11-24T03:15:22.123456Z");
    for bad in [
        "2026-11-24T03:15:22Z",         // no fraction
        "2026-11-24T03:15:22.123Z",     // three digits
        "2026-11-24T03:15:22.1234567Z", // seven digits
        "2026-11-24T03:15:22.123456+00:00",
        "2026-11-24t03:15:22.123456Z",
        "2026-11-24 03:15:22.123456Z",
        "2026-02-30T00:00:00.000000Z", // no such day
        "2025-02-29T00:00:00.000000Z", // not a leap year
        "2026-11-24T24:00:00.000000Z",
        "2026-11-24T23:59:60.000000Z", // leap second
        "0000-01-01T00:00:00.000000Z",
        "+2026-11-24T03:15:22.123456Z",
    ] {
        assert!(bad.parse::<Timestamp>().is_err(), "accepted {bad:?}");
    }
    assert!("2024-02-29T00:00:00.000000Z".parse::<Timestamp>().is_ok());
    assert!("2000-02-29T00:00:00.000000Z".parse::<Timestamp>().is_ok());
    assert!("1900-02-29T00:00:00.000000Z".parse::<Timestamp>().is_err());
}

#[test]
fn timestamps_from_os_logs_are_truncated_to_microseconds() {
    let t = Timestamp::parse_utc("2026-11-24T03:15:22.1234567Z").unwrap();
    assert_eq!(t.to_string(), "2026-11-24T03:15:22.123456Z");
    let t = Timestamp::parse_utc("2026-11-24T03:15:22Z").unwrap();
    assert_eq!(t.to_string(), "2026-11-24T03:15:22.000000Z");
    let t = Timestamp::parse_utc("2026-11-24T03:15:22.5Z").unwrap();
    assert_eq!(t.to_string(), "2026-11-24T03:15:22.500000Z");
    assert!(Timestamp::parse_utc("2026-11-24T03:15:22.Z").is_err());
    assert!(Timestamp::parse_utc("2026-11-24T03:15:22.1234567890Z").is_err());
}

#[test]
fn timestamp_bounds_and_epoch() {
    assert_eq!(
        Timestamp::from_unix_micros(0).unwrap().to_string(),
        "1970-01-01T00:00:00.000000Z"
    );
    assert_eq!(Timestamp::MIN.to_string(), "0001-01-01T00:00:00.000000Z");
    assert_eq!(Timestamp::MAX.to_string(), "9999-12-31T23:59:59.999999Z");
    assert!(Timestamp::from_unix_micros(Timestamp::MIN.unix_micros() - 1).is_none());
    assert!(Timestamp::from_unix_micros(Timestamp::MAX.unix_micros() + 1).is_none());
    assert_eq!(
        Timestamp::from_unix_micros(-1).unwrap().to_string(),
        "1969-12-31T23:59:59.999999Z"
    );
}

#[test]
fn sids_are_canonical() {
    for good in [
        "S-1-5-18",
        "S-1-0",
        "S-1-5-21-1004336348-1177238915-682003330-512",
        "S-1-4294967295-4294967295",
        "S-1-0x000100000000-1",
        "S-1-0xFFFFFFFFFFFF",
    ] {
        assert_eq!(good.parse::<Sid>().unwrap().as_str(), good);
    }
    for bad in [
        "",
        "S-1",
        "S-1-",
        "s-1-5-18",            // lowercase: normalise first
        "S-1-0x5-18",          // hex authority below 2^32: written in decimal
        "S-1-4294967296",      // 2^32 in decimal: written in hex
        "S-1-0x000100000000a", // too many hex digits
        "S-1-0x00010000000a",  // lowercase hex
        "S-2-5-18",
        "S-1-05-18",
        "S-1-5-018",
        "S-1-5-4294967296",
        "S-1-0x1000000000000",
        "S-1-5-18-",
        "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16",
        "S-1-5-+1",
    ] {
        assert!(bad.parse::<Sid>().is_err(), "accepted {bad:?}");
    }
}

#[test]
fn sids_normalise_os_spellings() {
    for (raw, canonical) in [
        ("s-1-5-18", "S-1-5-18"),
        ("S-1-0x5-18", "S-1-5-18"),
        ("S-1-0x100000000-1", "S-1-0x000100000000-1"),
        ("S-1-0xabcdefabcdef", "S-1-0xABCDEFABCDEF"),
    ] {
        assert_eq!(Sid::normalise(raw).unwrap().as_str(), canonical, "{raw}");
    }
    // A large authority in decimal is read, and written back in hex.
    assert_eq!(
        Sid::normalise("S-1-4294967296").unwrap().as_str(),
        "S-1-0x000100000000"
    );
    assert!(Sid::normalise("not a sid").is_err());
}

#[test]
fn sids_agree_with_the_file_identity_parser() {
    use palisade_fileid::fsctx::sid::Sid as FsSid;
    for (auth, subs) in [
        (5u64, vec![18u32]),
        (1 << 32, vec![1]),
        ((1 << 48) - 1, vec![]),
        (0, vec![0; 15]),
    ] {
        let fs = FsSid::new(auth, &subs).unwrap();
        let ours: Sid = fs.to_string().parse().unwrap();
        assert_eq!(ours, Sid::from(fs));
        assert_eq!(ours.as_str().parse::<FsSid>().unwrap(), fs);
    }
}

#[test]
fn hex_values_are_lowercase_and_sized() {
    let h: Sha256Hex = "ab".repeat(32).parse().unwrap();
    assert_eq!(h.to_string(), "ab".repeat(32));
    assert!("AB".repeat(32).parse::<Sha256Hex>().is_err());
    assert!("ab".repeat(31).parse::<Sha256Hex>().is_err());
    assert!(
        format!("0x{}", "ab".repeat(32))
            .parse::<Sha256Hex>()
            .is_err()
    );
    assert!("ab".repeat(20).parse::<Sha1Hex>().is_ok());
    assert!("ab".parse::<HexBytes>().is_ok());
    assert!("".parse::<HexBytes>().is_err());
    assert!("abc".parse::<HexBytes>().is_err());
    assert!("ab".repeat(65).parse::<HexBytes>().is_err());
}

#[test]
fn guids_are_canonical() {
    let g: Guid = "a244370e-44c9-4c06-b551-f6016e563076".parse().unwrap();
    assert_eq!(g.to_string(), "a244370e-44c9-4c06-b551-f6016e563076");
    for bad in [
        "{a244370e-44c9-4c06-b551-f6016e563076}",
        "A244370E-44C9-4C06-B551-F6016E563076",
        "a244370e44c94c06b551f6016e563076",
        "a244370e-44c9-4c06-b551-f6016e56307",
        "a244370e-44c9-4c06-b551f-6016e563076",
    ] {
        assert!(bad.parse::<Guid>().is_err(), "accepted {bad:?}");
    }
}

#[test]
fn ip_addresses_are_canonical() {
    for good in ["192.0.2.1", "2001:db8::1", "::1", "::ffff:192.0.2.1"] {
        assert!(good.parse::<IpAddress>().is_ok(), "{good}");
    }
    for bad in [
        "192.000.2.1",
        "2001:DB8::1",
        "2001:db8:0:0:0:0:0:1",
        "[::1]",
        "",
    ] {
        assert!(bad.parse::<IpAddress>().is_err(), "accepted {bad:?}");
    }
}

#[test]
fn severity_maps_to_syslog() {
    let codes: Vec<u8> = (0..=10)
        .map(|s| Severity::new(s).unwrap().syslog().code())
        .collect();
    assert_eq!(codes, [7, 6, 6, 6, 5, 5, 4, 4, 3, 2, 1]);
    assert!(Severity::new(11).is_none());
    assert!(serde_json::from_str::<Severity>("11").is_err());
    assert!(serde_json::from_str::<Severity>("-1").is_err());
    // Never emergency: that level belongs to the host OS.
    assert!((0..=10).all(|s| Severity::new(s).unwrap().syslog() != SyslogSeverity::Emergency));
}

#[test]
fn text_and_lists_are_bounded() {
    assert!(Name::new("").is_err());
    assert!(Name::new("x".repeat(256)).is_ok());
    assert!(Name::new("x".repeat(257)).is_err());
    // Characters, not bytes, as JSON Schema counts them.
    assert!(Name::new("\u{4e2d}".repeat(256)).is_ok());
    assert!(serde_json::from_value::<Name>(serde_json::json!("x".repeat(2000))).is_err());
    assert!(serde_json::from_value::<Name>(serde_json::json!("x".repeat(256))).is_ok());
    let too_many: Vec<String> = (0..33).map(|i| format!("\"10.0.0.{i}\"")).collect();
    let json = format!("[{}]", too_many.join(","));
    assert!(serde_json::from_str::<BoundedVec<IpAddress, 32>>(&json).is_err());
}

#[test]
fn labels_reject_duplicates_and_bad_keys() {
    assert!(serde_json::from_str::<Labels>(r#"{"team":"a","team":"b"}"#).is_err());
    assert!(serde_json::from_str::<Labels>(r#"{"Team":"a"}"#).is_err());
    assert!(serde_json::from_str::<Labels>(r#"{"team":""}"#).is_err());
    assert!(serde_json::from_str::<Labels>(r#"{"app.tier":"web"}"#).is_ok());
}

#[test]
fn event_mode_follows_policy_mode() {
    assert_eq!(EventMode::from_policy_mode(Mode::Disabled), None);
    assert_eq!(
        EventMode::from_policy_mode(Mode::Enforce),
        Some(EventMode::Enforce)
    );
    assert_eq!(
        EventMode::from_policy_mode(Mode::Audit),
        Some(EventMode::Audit)
    );
    assert_eq!(
        EventMode::from_policy_mode(Mode::Monitor),
        Some(EventMode::Monitor)
    );
    assert_eq!(
        EventMode::from_policy_mode(Mode::Learning),
        Some(EventMode::Learning)
    );
}

// ---------------------------------------------------------------- envelope

#[test]
fn minimal_event_reads_and_validates() {
    let event = Event::from_json(&minimal_json().to_string()).unwrap();
    assert_eq!(event, minimal());
    event.validate().unwrap();
    // Canonical form: compact, schema field order, unset optionals left out.
    assert_eq!(
        event.to_canonical_json().unwrap(),
        format!(
            concat!(
                r#"{{"schema_version":"1.0.0","event_id":"{u}","event_type":"agent.started","#,
                r#""category":"agent","action":"start","outcome":"info","severity":2,"#,
                r#""description":"The agent started.","ts":"2026-11-24T03:15:22.123456Z","#,
                r#""clock_synced":true,"tenant_id":"{u}","host":{{"id":"{u}"}},"seq":0}}"#
            ),
            u = UUID
        )
    );
}

#[test]
fn unknown_fields_are_rejected_everywhere() {
    for patch in [
        serde_json::json!({ "extra": 1 }),
        serde_json::json!({ "host": { "id": UUID, "extra": 1 } }),
        serde_json::json!({ "file": { "hashes": { "sha512": "00" } } }),
        serde_json::json!({ "process": { "parent": { "parent": {} } } }),
    ] {
        let json = with(patch.clone()).to_string();
        assert!(Event::from_json(&json).is_err(), "accepted {patch}");
    }
}

#[test]
fn null_is_never_a_value() {
    for patch in [
        serde_json::json!({ "prev_hash": serde_json::Value::Null, "seq": 1 }),
        serde_json::json!({ "file": serde_json::Value::Null }),
        serde_json::json!({ "mode": serde_json::Value::Null }),
        serde_json::json!({ "host": { "id": UUID, "name": serde_json::Value::Null } }),
        serde_json::json!({ "script": { "path": serde_json::Value::Null, "inline": true } }),
    ] {
        let mut value = minimal_json();
        for (k, v) in patch.as_object().unwrap() {
            value[k] = v.clone();
        }
        assert!(
            Event::from_json(&value.to_string()).is_err(),
            "accepted {patch}"
        );
    }
}

#[test]
fn version_peek_skips_other_values() {
    for v in [
        serde_json::json!(1),
        serde_json::json!([1, 2, 3]),
        serde_json::json!({ "a": [1, { "b": 2 }] }),
        serde_json::json!(true),
    ] {
        let json = with(serde_json::json!({ "schema_version": v })).to_string();
        assert!(
            matches!(
                Event::from_json(&json),
                Err(LoadError::MissingSchemaVersion)
            ),
            "{v}"
        );
    }
}

#[test]
fn versions_are_checked_before_fields() {
    let read = |v: &str| {
        Event::from_json(&with(serde_json::json!({ "schema_version": v, "extra": 1 })).to_string())
    };
    assert!(matches!(
        read("2.0.0"),
        Err(LoadError::UnsupportedSchemaVersion(_))
    ));
    assert!(matches!(
        read("0.9.0"),
        Err(LoadError::UnsupportedSchemaVersion(_))
    ));
    assert!(matches!(
        read("1.4.0"),
        Err(LoadError::NewerMinorVersion(_))
    ));
    for older_or_same in ["1.0.0", "1.0.1", "1.1.0", "1.1.7", "1.2.0", "1.3.0"] {
        assert!(
            matches!(read(older_or_same), Err(LoadError::Json(_))),
            "{older_or_same}: read, and the extra field fails"
        );
    }
    let missing = with(serde_json::json!({ "schema_version": null })).to_string();
    assert!(matches!(
        Event::from_json(&missing),
        Err(LoadError::MissingSchemaVersion)
    ));
    let bad = with(serde_json::json!({ "schema_version": "1.0" })).to_string();
    assert!(matches!(
        Event::from_json(&bad),
        Err(LoadError::MissingSchemaVersion)
    ));
}

#[test]
fn validate_reports_every_broken_rule() {
    let mut event = minimal();
    event.event_type = EventType::ExecDecision;
    event.seq = 5;
    event.script = Some(Script {
        path: Some(LongText::new("C:\\a.ps1").unwrap()),
        inline: true,
        ..Script::default()
    });
    let errors = event.validate().unwrap_err();
    let codes: Vec<_> = errors.iter().map(|e| (e.code, e.path)).collect();
    assert_eq!(
        codes,
        [
            (EventErrorCode::CategoryMismatch, "/category"),
            (EventErrorCode::MissingFieldSet(FieldSet::File), "/file"),
            (EventErrorCode::ChainLink, "/prev_hash"),
            (EventErrorCode::ScriptPathXorInline, "/script"),
        ]
    );
    let mut empty_script = minimal();
    empty_script.script = Some(Script::default());
    assert_eq!(
        empty_script.validate().unwrap_err()[0].code,
        EventErrorCode::ScriptPathXorInline
    );
    let mut first = minimal();
    first.prev_hash = Some(Hex::from_bytes([0; 32]));
    assert_eq!(
        first.validate().unwrap_err()[0].code,
        EventErrorCode::ChainLink
    );
}

#[test]
fn ism_0585_gaps_name_what_is_missing() {
    let mut event = minimal();
    assert_eq!(event.ism_0585_gaps(), ["user or process", "file name"]);
    event.user = Some(User {
        sid: Some("S-1-5-18".parse().unwrap()),
        ..User::default()
    });
    assert_eq!(event.ism_0585_gaps(), ["file name"]);
    event.native = Some(Native {
        clsid: Some(Guid::from_bytes([1; 16])),
        ..Native::default()
    });
    assert!(event.ism_0585_gaps().is_empty());
}

#[test]
fn registry_strings_round_trip() {
    for t in EventType::ALL {
        assert_eq!(t.as_str().parse::<EventType>().unwrap(), t);
        assert_eq!(serde_json::to_value(t).unwrap(), t.as_str());
        assert!(!t.description().is_empty());
    }
    assert!("exec.unknown".parse::<EventType>().is_err());
}

// ---------------------------------------------------------------- properties

fn compiled_schema() -> (boon::Schemas, boon::SchemaIndex) {
    let mut schemas = boon::Schemas::new();
    let mut compiler = boon::Compiler::new();
    compiler.enable_format_assertions();
    compiler
        .add_resource(schema::SCHEMA_ID, schema::generate())
        .unwrap();
    let index = compiler.compile(schema::SCHEMA_ID, &mut schemas).unwrap();
    (schemas, index)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(2_000)
    ))]

    #[test]
    fn generated_events_validate(event in arbitrary::event()) {
        prop_assert_eq!(event.validate(), Ok(()));
    }

    #[test]
    fn json_round_trip_is_lossless(event in arbitrary::event()) {
        let json = event.to_canonical_json().unwrap();
        let again = Event::from_json(&json).unwrap();
        prop_assert_eq!(&again, &event);
        prop_assert_eq!(again.to_canonical_json().unwrap(), json);
    }

    #[test]
    fn generated_events_match_the_json_schema(event in arbitrary::event()) {
        thread_local! {
            static SCHEMA: (boon::Schemas, boon::SchemaIndex) = compiled_schema();
        }
        let value = serde_json::to_value(&event).unwrap();
        SCHEMA.with(|(schemas, index)| {
            if let Err(e) = schemas.validate(&value, *index) {
                panic!("{e:#}\n{value:#}");
            }
        });
    }

    #[test]
    fn timestamp_text_round_trips(micros in Timestamp::MIN.unix_micros()..=Timestamp::MAX.unix_micros()) {
        let t = Timestamp::from_unix_micros(micros).unwrap();
        let text = t.to_string();
        prop_assert_eq!(text.parse::<Timestamp>().unwrap(), t);
        prop_assert_eq!(Timestamp::parse_utc(&text).unwrap(), t);
    }
}

// ---------------------------------------------------------------- 1.1 values

#[test]
fn dns_names_are_canonical() {
    for good in [
        "a",
        "files.example.org",
        "_ldap._tcp.example.org",
        "xn--bcher-kva.example",
        "1.2.3",
    ] {
        assert_eq!(good.parse::<DnsName>().unwrap().as_str(), good);
    }
    let long_label = "a".repeat(64);
    // 253 characters is the limit; 255 is over it.
    let at_limit = ["a"; 127].join(".");
    assert!(at_limit.parse::<DnsName>().is_ok());
    let too_long = ["a"; 128].join(".");
    for bad in [
        "",
        "Files.example.org",
        "files.example.org.",
        "a..b",
        "-a.example",
        "a-.example",
        "a b",
        "b\u{fc}cher.example",
        long_label.as_str(),
        too_long.as_str(),
    ] {
        assert!(bad.parse::<DnsName>().is_err(), "accepted {bad:?}");
    }
    assert_eq!(
        DnsName::normalise("Files.Example.ORG.").unwrap().as_str(),
        "files.example.org"
    );
    assert!(DnsName::normalise("a..b").is_err());
}

#[test]
fn registry_keys_are_canonical() {
    for good in [
        "HKEY_LOCAL_MACHINE",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies",
        "HKEY_USERS\\S-1-5-21-1-2-3-1001\\Software",
        "HKEY_CURRENT_USER\\a b\\c/d",
    ] {
        assert_eq!(good.parse::<RegistryKey>().unwrap().as_str(), good);
    }
    let long = format!("HKEY_USERS\\{}", "x".repeat(256));
    for bad in [
        "",
        "HKLM\\SOFTWARE",
        "hkey_local_machine\\SOFTWARE",
        "HKEY_LOCAL_MACHINE\\",
        "HKEY_LOCAL_MACHINE\\\\SOFTWARE",
        "HKEY_LOCAL_MACHINEX",
        "\\REGISTRY\\MACHINE\\SOFTWARE",
        long.as_str(),
    ] {
        assert!(bad.parse::<RegistryKey>().is_err(), "accepted {bad:?}");
    }
    for (raw, canonical) in [
        ("HKLM\\SOFTWARE", "HKEY_LOCAL_MACHINE\\SOFTWARE"),
        ("hklm\\SOFTWARE\\", "HKEY_LOCAL_MACHINE\\SOFTWARE"),
        ("\\REGISTRY\\MACHINE\\SYSTEM", "HKEY_LOCAL_MACHINE\\SYSTEM"),
        ("\\Registry\\User\\S-1-5-18", "HKEY_USERS\\S-1-5-18"),
        ("HKCU", "HKEY_CURRENT_USER"),
        ("HKEY_CLASSES_ROOT\\.ps1", "HKEY_CLASSES_ROOT\\.ps1"),
    ] {
        assert_eq!(
            RegistryKey::normalise(raw).unwrap().as_str(),
            canonical,
            "{raw}"
        );
    }
    for bad in [
        "HKLMX\\a",
        "\\REGISTRY\\MACHINEX",
        "SOFTWARE\\x",
        "HKLM\\\\x",
    ] {
        assert!(RegistryKey::normalise(bad).is_err(), "normalised {bad:?}");
    }
}

#[test]
fn json_pointers_are_canonical() {
    for good in ["/a", "/rules/0/name", "/a~0b/c~1d", "/", "//"] {
        assert!(good.parse::<JsonPointer>().is_ok(), "{good}");
    }
    for bad in ["", "a", "/a~", "/a~2", "/~x"] {
        assert!(bad.parse::<JsonPointer>().is_err(), "accepted {bad:?}");
    }
}

#[test]
fn json_values_have_one_form() {
    let read = |s: &str| serde_json::from_str::<JsonValue>(s);
    let v = read(r#"{"b":[1,-2,true,"x"],"a":{"c":18446744073709551615}}"#).unwrap();
    // Keys are written sorted; integers keep their exact value.
    assert_eq!(
        serde_json::to_string(&v).unwrap(),
        r#"{"a":{"c":18446744073709551615},"b":[1,-2,true,"x"]}"#
    );
    // One form per integer: a small `u64` and the same `i64` are equal.
    assert_eq!(
        JsonValue::new(serde_json::json!(5u64)).unwrap(),
        JsonValue::new(serde_json::json!(5i64)).unwrap()
    );
    assert_eq!(read("5").unwrap().to_json(), serde_json::json!(5));
    assert_eq!(
        read("18446744073709551615").unwrap().to_json(),
        serde_json::json!(u64::MAX)
    );
    // The checked constructor applies the reader's rules.
    for bad in [
        serde_json::json!(null),
        serde_json::json!([1, null]),
        serde_json::json!(1.5),
        serde_json::json!("x".repeat(4097)),
        serde_json::json!({ "k".repeat(257): 1 }),
        serde_json::Value::Array(vec![serde_json::json!(1); 1024]),
    ] {
        assert!(JsonValue::new(bad.clone()).is_err(), "built {bad}");
    }
    let deep = (0..16).fold(serde_json::json!(1), |v, _| serde_json::json!([v]));
    assert!(JsonValue::new(deep).is_err(), "17 levels");
    let ok = serde_json::json!({ "b": [1, "x", true], "a": { "c": -1 } });
    assert_eq!(JsonValue::new(ok.clone()).unwrap().to_json(), ok);
    for bad in [
        "null",
        "[1,null]",
        r#"{"a":null}"#,
        "1.5",
        "1e3",
        r#"{"a":1,"a":2}"#,
        "-9223372036854775809",
    ] {
        assert!(read(bad).is_err(), "accepted {bad}");
    }
    // Depth: 16 levels are accepted, 17 are not.
    let nest = |n: usize| format!("{}1{}", "[".repeat(n - 1), "]".repeat(n - 1));
    assert!(read(&nest(16)).is_ok());
    assert!(read(&nest(17)).is_err());
    // Size: 1024 values in all.
    let items = |n: usize| format!("[{}]", vec!["1"; n].join(","));
    assert!(read(&items(1023)).is_ok());
    assert!(read(&items(1024)).is_err());
    // String and key limits.
    assert!(read(&format!("\"{}\"", "x".repeat(4096))).is_ok());
    assert!(read(&format!("\"{}\"", "x".repeat(4097))).is_err());
    assert!(read(&format!("{{\"{}\":1}}", "k".repeat(257))).is_err());
}

#[test]
fn sorted_sets_have_one_form() {
    type Set = SortedSet<AuditPolicyChange, 4>;
    let set: Set = serde_json::from_str(r#"["success_added","failure_added"]"#).unwrap();
    assert_eq!(
        set.as_slice(),
        [
            AuditPolicyChange::SuccessAdded,
            AuditPolicyChange::FailureAdded
        ]
    );
    for bad in [
        r#"["failure_added","success_added"]"#,
        r#"["success_added","success_added"]"#,
    ] {
        assert!(serde_json::from_str::<Set>(bad).is_err(), "accepted {bad}");
    }
    let built = Set::new(vec![
        AuditPolicyChange::FailureAdded,
        AuditPolicyChange::SuccessAdded,
        AuditPolicyChange::FailureAdded,
    ])
    .unwrap();
    assert_eq!(built, set);
}

#[test]
fn new_flags_are_written_only_when_set() {
    let reg = |extra: serde_json::Value| {
        let mut v = with(serde_json::json!({ "schema_version": "1.1.0" }));
        v["registry"] = extra;
        Event::from_json(&v.to_string())
    };
    assert!(reg(serde_json::json!({ "default_value": true })).is_ok());
    assert!(reg(serde_json::json!({ "default_value": false })).is_err());
    assert!(reg(serde_json::json!({ "new": { "preview": "x", "truncated": false } })).is_err());
    // `script.inline` keeps its 1.0 reading of `false`.
    let mut v = minimal_json();
    v["script"] = serde_json::json!({ "path": "a.ps1", "inline": false });
    assert!(Event::from_json(&v.to_string()).is_ok());
}

// ---------------------------------------------------------------- 1.1 rules

fn v11(patch: serde_json::Value) -> Event {
    let mut v = with(serde_json::json!({ "schema_version": "1.1.0" }));
    for (k, val) in patch.as_object().unwrap() {
        v[k] = val.clone();
    }
    Event::from_json(&v.to_string()).unwrap()
}

fn codes(event: &Event) -> Vec<EventErrorCode> {
    event
        .validate()
        .err()
        .unwrap_or_default()
        .into_iter()
        .map(|e| e.code)
        .collect()
}

#[test]
fn a_version_label_covers_everything_the_event_uses() {
    // A 1.0 event is valid at 1.0 and at 1.1.
    let old = minimal();
    assert_eq!(old.min_version(), V1_0);
    let mut relabelled = old.clone();
    relabelled.schema_version = V1_1;
    assert_eq!(relabelled.validate(), Ok(()));
    // Each 1.1 part makes a 1.0 label invalid.
    for patch in [
        serde_json::json!({ "network": {} }),
        serde_json::json!({ "fim": {} }),
        serde_json::json!({ "source": { "kind": "third_party", "format": "generic" } }),
        serde_json::json!({ "source": { "kind": "os_security", "rule_name": "x" } }),
        serde_json::json!({ "script": { "inline": true, "text": "x" } }),
        serde_json::json!({
            "event_type": "process.created", "category": "execution", "process": {}
        }),
    ] {
        let mut event = v11(patch.clone());
        assert_eq!(event.min_version(), V1_1, "{patch}");
        assert_eq!(event.validate(), Ok(()), "{patch}");
        event.schema_version = V1_0;
        assert_eq!(codes(&event), [EventErrorCode::NewerThanVersion], "{patch}");
    }
}

#[test]
fn the_1_2_policy_integrity_types_need_a_1_2_label() {
    // #225's integrity types are the only 1.2 additions, and each needs a
    // 1.2 label: an older reader would refuse the unknown type.
    let v1_2: Vec<&str> = EventType::ALL
        .iter()
        .filter(|t| t.since() == V1_2)
        .map(|t| t.as_str())
        .collect();
    assert_eq!(
        v1_2,
        [
            "policy.signature.invalid",
            "policy.rollback_rejected",
            "policy.target_mismatch",
            "policy.stale",
            "policy.lkg_loaded",
            "policy.emergency_loaded",
            "policy.schema_unsupported",
            "tamper.policy.rollback_suspected",
        ]
    );
    for t in EventType::ALL.iter().filter(|t| t.since() == V1_2) {
        let mut patch = serde_json::json!({
            "event_type": t.as_str(),
            "category": serde_json::to_value(t.category()).unwrap(),
        });
        if t.required().contains(&FieldSet::Policy) {
            patch["policy"] = serde_json::json!({ "version": 7 });
        }
        patch["schema_version"] = "1.2.0".into();
        let mut event = Event::from_json(&with(patch).to_string()).unwrap();
        assert_eq!(event.min_version(), V1_2, "{t}");
        assert_eq!(event.validate(), Ok(()), "{t}");
        event.schema_version = V1_1;
        assert_eq!(codes(&event), [EventErrorCode::NewerThanVersion], "{t}");
    }
}

#[test]
fn policy_kid_needs_a_1_3_label() {
    // #325: the signing key of a policy bundle is the only 1.3 addition.
    let added: Vec<&str> = ADDED
        .iter()
        .filter(|(_, v)| *v == V1_3)
        .map(|(p, _)| *p)
        .collect();
    assert_eq!(added, ["/policy/kid"]);
    assert!(EventType::ALL.iter().all(|t| t.since() < V1_3));
    let mut event = Event::from_json(
        &with(serde_json::json!({
            "schema_version": "1.3.0",
            "event_type": "policy.applied",
            "category": "policy",
            "policy": { "version": 4, "kid": "06e3fd8fda29bb60ab59557de61edb0a" },
        }))
        .to_string(),
    )
    .unwrap();
    assert_eq!(event.min_version(), V1_3);
    assert_eq!(event.validate(), Ok(()));
    let kid = event.policy.as_ref().and_then(|p| p.kid).unwrap();
    assert_eq!(kid.to_string(), "06e3fd8fda29bb60ab59557de61edb0a");
    event.schema_version = V1_2;
    assert_eq!(codes(&event), [EventErrorCode::NewerThanVersion]);
    // Without the key ID, the same event is a 1.0 event again.
    if let Some(p) = event.policy.as_mut() {
        p.kid = None;
    }
    assert_eq!(event.min_version(), V1_0);
}

#[test]
fn every_1_1_field_set_and_type_is_newer_than_1_0() {
    for set in FieldSet::ALL {
        assert_eq!(set.since() == V1_1, pointer_since(set.pointer()) == V1_1);
    }
    for t in EventType::ALL {
        assert!(t.since() <= CURRENT, "{}", t.as_str());
        assert!(
            t.required().iter().all(|s| s.since() <= t.since()),
            "{}",
            t.as_str()
        );
    }
    for kind in SourceKind::ALL {
        assert_eq!(kind.since() == V1_1, kind == SourceKind::ThirdParty);
    }
}

#[test]
fn the_1_1_cross_field_rules_hold() {
    for (patch, code) in [
        (
            serde_json::json!({ "source": { "kind": "third_party" } }),
            EventErrorCode::SourceFormat,
        ),
        (
            serde_json::json!({ "source": { "kind": "os_security", "format": "generic" } }),
            EventErrorCode::SourceFormat,
        ),
        (
            serde_json::json!({ "network": { "resolution": "dns" } }),
            EventErrorCode::ResolutionWithoutHostname,
        ),
        (
            serde_json::json!({ "registry": { "value_name": "Run", "default_value": true } }),
            EventErrorCode::RegistryValueName,
        ),
        (
            serde_json::json!({ "registry": { "old": { "truncated": true } } }),
            EventErrorCode::TruncatedWithoutPreview,
        ),
        (
            serde_json::json!({ "admin": { "changes": [{ "op": "add", "path": "/a" }] } }),
            EventErrorCode::ChangeValues,
        ),
        (
            serde_json::json!({ "admin": { "changes": [{ "op": "remove", "path": "/a", "old": 1, "new": 2 }] } }),
            EventErrorCode::ChangeValues,
        ),
    ] {
        assert_eq!(codes(&v11(patch.clone())), [code], "{patch}");
    }
    for ok in [
        serde_json::json!({ "network": { "remote_hostname": "a.example", "resolution": "dns" } }),
        serde_json::json!({ "registry": { "default_value": true } }),
        serde_json::json!({ "registry": { "new": { "preview": "x", "truncated": true } } }),
        serde_json::json!({ "admin": { "changes": [
            { "op": "add", "path": "/a", "new": 1 },
            { "op": "remove", "path": "/b", "old": "x" },
            { "op": "replace", "path": "/c", "old": [], "new": {} }
        ] } }),
    ] {
        assert_eq!(codes(&v11(ok.clone())), [], "{ok}");
    }
}

#[test]
fn ism_0585_accepts_network_device_and_registry_objects() {
    for (patch, gaps) in [
        (
            serde_json::json!({ "network": { "url": "https://a.example/" } }),
            0,
        ),
        (
            serde_json::json!({ "network": { "remote_ip": "192.0.2.1" } }),
            0,
        ),
        (serde_json::json!({ "network": { "remote_port": 443 } }), 1),
        (
            serde_json::json!({ "device": { "instance_id": "USB\\VID_1" } }),
            0,
        ),
        (serde_json::json!({ "device": { "vendor_id": 1 } }), 1),
        (
            serde_json::json!({ "registry": { "key": "HKEY_USERS" } }),
            0,
        ),
        (
            serde_json::json!({ "registry": { "value_name": "Run" } }),
            1,
        ),
    ] {
        let mut patch = patch;
        patch["user"] = serde_json::json!({ "sid": "S-1-5-18" });
        let event = v11(patch.clone());
        assert_eq!(event.ism_0585_gaps().len(), gaps, "{patch}");
    }
}

#[test]
fn every_added_pointer_raises_the_minimum_version() {
    // `min_version` checks each addition by hand; this ties it to `ADDED`.
    for (pointer, since) in ADDED {
        let keys: Vec<&str> = pointer.trim_start_matches('/').split('/').collect();
        let mut value = with(serde_json::json!({ "schema_version": "1.1.0" }));
        let leaf = match keys.as_slice() {
            [set] => {
                value[*set] = serde_json::json!({});
                *set
            }
            ["source", field] => {
                value["source"] = serde_json::json!({ "kind": "third_party", "format": "generic" });
                if *field == "rule_name" {
                    value["source"] =
                        serde_json::json!({ "kind": "os_security", "rule_name": "R" });
                }
                field
            }
            ["script", "text"] => {
                value["script"] = serde_json::json!({ "inline": true, "text": "x" });
                "text"
            }
            ["policy", "kid"] => {
                value["policy"] = serde_json::json!({ "kid": "06e3fd8fda29bb60ab59557de61edb0a" });
                "kid"
            }
            other => panic!("add a case for {other:?}"),
        };
        let event =
            Event::from_json(&value.to_string()).unwrap_or_else(|e| panic!("{pointer}: {e}"));
        assert_eq!(event.min_version(), *since, "{pointer} ({leaf})");
    }
}

#[test]
fn json_pointer_schema_pattern_is_unambiguous() {
    // Every token excludes `/`, so the pattern cannot backtrack between the
    // inner and outer repetition.
    let schema = schema::generate();
    assert_eq!(
        schema["$defs"]["JsonPointer"]["pattern"],
        "^(/([^~/]|~[01])*)+$"
    );
}
