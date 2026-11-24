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
        read("1.1.0"),
        Err(LoadError::NewerMinorVersion(_))
    ));
    assert!(
        matches!(read("1.0.1"), Err(LoadError::Json(_))),
        "same minor: read, and the extra field fails"
    );
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
