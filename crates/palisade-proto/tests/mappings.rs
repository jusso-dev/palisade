//! Golden tests for the shipped mapping files.
//!
//! Each fixture in `tests/fixtures/mappings/<name>.json` is a synthetic,
//! anonymised source record (with any correlated signature records), and
//! `<name>.expected.json` is the canonical event it must produce. Regenerate
//! the expected files after an intended change with:
//!
//! ```sh
//! PALISADE_BLESS=1 cargo test -p palisade-proto --test mappings
//! ```
//!
//! Every expected event must also pass the committed JSON Schema and the
//! ISM-0585 field checklist, and every entry (every source event ID and
//! each canonical type it can map to) must have a fixture.

#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use palisade_proto::events::{
    EventType, Host, HostId, Labels, Outcome, SourceKind, TenantId, Timestamp, schema,
};
use palisade_proto::mapping::{Envelope, MappingSet, Record};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    source: SourceKind,
    record: RecordDoc,
    #[serde(default)]
    signatures: Vec<RecordDoc>,
    /// Source fields the mapping must report as dropped.
    #[serde(default)]
    dropped: Vec<String>,
    /// The `(received, announced)` signature counts, when records are missing.
    #[serde(default)]
    signatures_incomplete: Option<(usize, u64)>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordDoc {
    event_id: u32,
    time_created: String,
    #[serde(default)]
    record_id: Option<u64>,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    activity_id: Option<String>,
    fields: BTreeMap<String, String>,
}

impl RecordDoc {
    fn into_record(self) -> Record {
        Record {
            event_id: self.event_id,
            time_created: Timestamp::parse_utc(&self.time_created).unwrap(),
            record_id: self.record_id,
            channel: self.channel,
            activity_id: self.activity_id.map(|a| a.parse().unwrap()),
            fields: self.fields,
        }
    }
}

fn envelope() -> Envelope {
    let id = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f".parse().unwrap();
    let host = serde_json::from_value::<Host>(serde_json::json!({
        "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60",
        "name": "WS-0001",
        "os": "Windows 11 Enterprise",
        "os_build": "26100.2314",
        "arch": "x86_64",
        "agent_version": "0.1.0"
    }))
    .unwrap();
    assert_eq!(
        host.id,
        HostId("01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60".parse().unwrap())
    );
    Envelope {
        event_id: id,
        tenant_id: TenantId("01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e61".parse().unwrap()),
        host,
        seq: 41,
        prev_hash: Some("5e".repeat(32).parse().unwrap()),
        clock_synced: true,
        ts_agent_monotonic: Some(123_456_789),
        clock_skew_ms: Some(-3),
        labels: Labels::default(),
    }
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mappings")
}

fn fixtures() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = fs::read_dir(fixture_dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            let name = p.file_name().unwrap().to_string_lossy();
            name.ends_with(".json") && !name.ends_with(".expected.json")
        })
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no mapping fixtures");
    paths
}

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

#[test]
fn golden_fixtures_map_to_expected_events() {
    let set = MappingSet::builtin().unwrap();
    let (schemas, index) = compiled_schema();
    let bless = std::env::var_os("PALISADE_BLESS").is_some();
    let mut covered: BTreeSet<(SourceKind, u32, EventType)> = BTreeSet::new();
    for path in fixtures() {
        let name = path.display().to_string();
        let fixture: Fixture = serde_json::from_str(&fs::read_to_string(&path).unwrap())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let record = fixture.record.into_record();
        let signatures: Vec<Record> = fixture
            .signatures
            .into_iter()
            .map(RecordDoc::into_record)
            .collect();
        let mapped = set
            .map(fixture.source, &record, &signatures, &envelope())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let dropped: Vec<&str> = mapped.dropped.iter().map(|d| d.field.as_str()).collect();
        assert_eq!(dropped, fixture.dropped, "{name}: dropped fields");
        assert_eq!(
            mapped.signatures_incomplete, fixture.signatures_incomplete,
            "{name}: signature counts"
        );
        covered.insert((fixture.source, record.event_id, mapped.event.event_type));

        let value = serde_json::to_value(&mapped.event).unwrap();
        if let Err(e) = schemas.validate(&value, index) {
            panic!("{name}: the mapped event fails the JSON Schema: {e:#}");
        }
        let event = &mapped.event;
        if event.event_type.as_str().ends_with(".decision") {
            assert!(
                event.ism_0585_gaps().is_empty(),
                "{name}: ISM-0585 gaps {:?}",
                event.ism_0585_gaps()
            );
        }

        let expected_path = path.with_extension("expected.json");
        // Serialise the event itself, not the `Value`, so the text is in
        // schema field order whether or not `serde_json`'s `preserve_order`
        // feature is enabled elsewhere in the build.
        let mut text = serde_json::to_string_pretty(event).unwrap();
        text.push('\n');
        if bless {
            fs::write(&expected_path, &text).unwrap();
            continue;
        }
        let expected = fs::read_to_string(&expected_path)
            .unwrap_or_else(|_| panic!("{name} has no .expected.json; bless it"))
            .replace("\r\n", "\n");
        assert!(
            expected == text,
            "{name}: the mapped event differs from {}.\nGot:\n{text}",
            expected_path.display()
        );
    }
    for source in [
        SourceKind::OsCodeIntegrity,
        SourceKind::OsLegacyRuleCollection,
    ] {
        for id in set.event_ids(source) {
            for ty in set.canonical_types(source, id) {
                assert!(
                    covered.contains(&(source, id, ty)),
                    "{} event {id} as `{}` has no fixture",
                    source.as_str(),
                    ty.as_str()
                );
            }
        }
    }
}

/// The two acceptance cases of #196: an enforced block from the code
/// integrity log, and a script block from the rule-collection log, both with
/// file name, hashes, signer, user, host and time.
#[test]
fn acceptance_enforced_block_and_script_block() {
    let set = MappingSet::builtin().unwrap();
    for (file, ty) in [
        ("ci_3077_exe.json", EventType::ExecDecision),
        ("rc_8029_script.json", EventType::ScriptDecision),
    ] {
        let fixture: Fixture =
            serde_json::from_str(&fs::read_to_string(fixture_dir().join(file)).unwrap()).unwrap();
        let record = fixture.record.into_record();
        let signatures: Vec<Record> = fixture
            .signatures
            .into_iter()
            .map(RecordDoc::into_record)
            .collect();
        let event = set
            .map(fixture.source, &record, &signatures, &envelope())
            .unwrap()
            .event;
        assert_eq!(event.event_type, ty, "{file}");
        assert_eq!(event.outcome, Outcome::Blocked, "{file}");
        let f = event.file.as_ref().unwrap();
        assert!(f.path.is_some(), "{file}: file name");
        assert!(
            f.hashes.sha256.is_some() || f.hashes.authenticode_sha256.is_some(),
            "{file}: hashes"
        );
        assert!(!f.signers.is_empty(), "{file}: signer");
        assert!(
            f.signers.as_slice()[0].publisher.is_some(),
            "{file}: signer publisher"
        );
        assert!(
            event.user.as_ref().and_then(|u| u.sid.as_ref()).is_some(),
            "{file}: user"
        );
        assert!(event.host.name.is_some(), "{file}: host");
        assert_eq!(event.ts.to_string().len(), 27, "{file}: time");
        assert!(event.ism_0585_gaps().is_empty(), "{file}");
    }
}

#[test]
fn malformed_fixture_values_do_not_stop_the_event() {
    // A record whose hash field is garbage still maps, without the hash.
    let set = MappingSet::builtin().unwrap();
    let mut fields = BTreeMap::new();
    fields.insert(
        "FileName".to_owned(),
        "\\Device\\HarddiskVolume3\\x.exe".to_owned(),
    );
    fields.insert("SHA256FlatHash".to_owned(), "not hex".to_owned());
    fields.insert("System.UserID".to_owned(), "S-1-5-18".to_owned());
    let record = Record {
        event_id: 3077,
        time_created: Timestamp::parse_utc("2026-11-24T03:15:22Z").unwrap(),
        record_id: None,
        channel: None,
        activity_id: None,
        fields,
    };
    let mapped = set
        .map(SourceKind::OsCodeIntegrity, &record, &[], &envelope())
        .unwrap();
    assert_eq!(mapped.dropped.len(), 1);
    assert!(mapped.event.file.unwrap().hashes.sha256.is_none());
}
