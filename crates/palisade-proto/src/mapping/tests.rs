//! Unit tests for the mapping engine and the lints on mapping files. The
//! golden tests for the shipped files are in `tests/mappings.rs`.

// Tests may index: a panic is a test failure.
#![allow(clippy::indexing_slicing)]

use super::targets::{EVENT_TARGETS, Kind, SIGNER_TARGETS};
use super::*;
use crate::events::{Category, HostId, schema};

const UUID: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f";

fn envelope() -> Envelope {
    let id: Uuid7 = UUID.parse().unwrap();
    Envelope {
        event_id: id,
        tenant_id: TenantId(id),
        host: Host {
            id: HostId(id),
            name: None,
            fqdn: None,
            domain: None,
            os: None,
            os_build: None,
            arch: None,
            agent_version: None,
            ips: Default::default(),
            groups: Default::default(),
        },
        seq: 0,
        prev_hash: None,
        clock_synced: true,
        ts_agent_monotonic: None,
        clock_skew_ms: None,
        labels: Labels::default(),
    }
}

fn record(event_id: u32, fields: &[(&str, &str)]) -> Record {
    Record {
        event_id,
        time_created: Timestamp::parse_utc("2026-11-24T03:15:22.1234567Z").unwrap(),
        record_id: Some(7),
        channel: None,
        activity_id: Some("a244370e-44c9-4c06-b551-f6016e563076".parse().unwrap()),
        fields: fields
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    }
}

/// A one-entry mapping file around `entry`, which is indented as a list item.
fn file_with(entry: &str) -> String {
    format!("schema_version: 1.0.0\nsource: os_code_integrity\nentries:\n{entry}")
}

const GOOD_ENTRY: &str = "  - source_event_id: 1
    canonical_type: exec.decision
    action: execute
    outcome: blocked
    description: Blocked.
    field_map:
      File: /file/path
      Pid: /process/pid
";

fn load_error(entry: &str) -> String {
    MappingSet::from_yaml("t.yaml", &file_with(entry))
        .unwrap_err()
        .to_string()
}

// ---------------------------------------------------------------- targets

/// Resolves a JSON Pointer through the generated schema: `properties`,
/// `$ref`, nullable `anyOf`, and array `items`.
fn schema_node<'a>(
    root: &'a serde_json::Value,
    mut node: &'a serde_json::Value,
    key: &str,
) -> Option<&'a serde_json::Value> {
    loop {
        if let Some(r) = node.get("$ref").and_then(|r| r.as_str()) {
            node = root.pointer(r.strip_prefix('#')?)?;
            continue;
        }
        if let Some(any) = node.get("anyOf").and_then(|a| a.as_array()) {
            node = any
                .iter()
                .find(|s| s.get("type") != Some(&serde_json::json!("null")))?;
            continue;
        }
        if node.get("properties").is_none()
            && let Some(items) = node.get("items")
        {
            node = items;
            continue;
        }
        break;
    }
    node.get("properties")?.get(key)
}

fn schema_leaf(pointer: &str) -> Option<serde_json::Value> {
    let root = schema::generate();
    let mut node = &root;
    for key in pointer.trim_start_matches('/').split('/') {
        // `0`: the first item of an array; `schema_node` follows `items`.
        if key == "0" {
            if node.get("type") != Some(&serde_json::json!("array")) {
                return None;
            }
            node = node.get("items")?;
            continue;
        }
        node = schema_node(&root, node, key)?;
    }
    Some(node.clone())
}

/// Resolves `$ref` and returns the enum values a schema node allows.
fn schema_enum(node: &serde_json::Value) -> Option<Vec<String>> {
    let root = schema::generate();
    let mut node = node.clone();
    while let Some(r) = node.get("$ref").and_then(|r| r.as_str()) {
        node = root.pointer(r.strip_prefix('#')?)?.clone();
    }
    if let Some(items) = node.get("items") {
        return schema_enum(items);
    }
    let options = node.get("oneOf")?.as_array()?;
    options
        .iter()
        .map(|o| o.get("const")?.as_str().map(str::to_owned))
        .collect()
}

#[test]
fn enum_targets_match_the_schema() {
    for (pointer, kind) in EVENT_TARGETS {
        let (Kind::Enum(values) | Kind::EnumSet(values)) = kind else {
            continue;
        };
        let leaf = schema_leaf(pointer).unwrap();
        let schema_values = schema_enum(&leaf).unwrap_or_else(|| panic!("{pointer}: not an enum"));
        assert_eq!(*values, schema_values.as_slice(), "{pointer}");
        if matches!(kind, Kind::EnumSet(_)) {
            assert_eq!(
                leaf.get("uniqueItems"),
                Some(&serde_json::json!(true)),
                "{pointer}"
            );
        }
    }
}

#[test]
fn principals_and_json_values_are_not_targets() {
    for (pointer, _) in EVENT_TARGETS {
        for forbidden in [
            "/admin/",
            "/approval/decided_by",
            "/elevation/approver",
            "/probe/expected",
            "/probe/observed",
        ] {
            assert!(!pointer.starts_with(forbidden), "{pointer}");
        }
    }
}

#[test]
fn every_target_exists_in_the_schema() {
    for (pointer, _) in EVENT_TARGETS {
        assert!(
            schema_leaf(pointer).is_some(),
            "{pointer} is not in the event schema"
        );
    }
    for (field, _) in SIGNER_TARGETS {
        let pointer = format!("{SIGNERS_POINTER}/{field}");
        assert!(
            schema_leaf(&pointer).is_some(),
            "{pointer} is not in the event schema"
        );
    }
    assert!(schema_leaf("/file/no_such_field").is_none());
}

#[test]
fn agent_owned_and_entry_owned_fields_are_not_targets() {
    for pointer in [
        "/event_id",
        "/seq",
        "/prev_hash",
        "/tenant_id",
        "/host/id",
        "/host/name",
        "/clock_synced",
        "/ts",
        "/event_type",
        "/category",
        "/outcome",
        "/mode",
        "/severity",
        "/source/kind",
        "/labels",
        "/schema_version",
    ] {
        assert!(
            targets::event_target(pointer).is_none(),
            "{pointer} is writable"
        );
    }
}

#[test]
fn kinds_normalise_os_spellings() {
    let read = |kind: Kind, raw: &str| kind.read(raw).unwrap().unwrap();
    assert_eq!(
        read(Kind::Sha1, &format!("0x{}", "AB".repeat(20))),
        "ab".repeat(20)
    );
    assert_eq!(
        read(Kind::Guid, "{A244370E-44C9-4C06-B551-F6016E563076}"),
        "a244370e-44c9-4c06-b551-f6016e563076"
    );
    assert_eq!(
        read(Kind::Unsigned(u64::from(u32::MAX)), "0xC0000428"),
        0xc000_0428u32
    );
    assert_eq!(read(Kind::Unsigned(255), "12"), 12);
    assert_eq!(read(Kind::Bool, "True"), true);
    assert_eq!(read(Kind::Bool, "0"), false);
    assert_eq!(Kind::Sha256.read("").unwrap(), None);
    assert!(Kind::Unsigned(255).read("256").is_err());
    assert!(Kind::Unsigned(255).read("-1").is_err());
    assert!(Kind::Unsigned(255).read("0x").is_err());
    assert!(Kind::Sha256.read("abcd").is_err());
    assert!(Kind::Bool.read("yes").is_err());
    assert!(Kind::Text(3).read("abcd").is_err());
    assert!(Kind::Sid.read("not-a-sid").is_err());
}

// ---------------------------------------------------------------- file lints

#[test]
fn a_good_file_loads() {
    let set = MappingSet::from_yaml("t.yaml", &file_with(GOOD_ENTRY)).unwrap();
    assert_eq!(set.event_ids(SourceKind::OsCodeIntegrity), [1]);
    assert_eq!(
        set.canonical_types(SourceKind::OsCodeIntegrity, 1),
        [EventType::ExecDecision]
    );
}

#[test]
fn unknown_canonical_fields_are_rejected() {
    let e = load_error(&GOOD_ENTRY.replace("/file/path", "/file/nope"));
    assert!(
        e.contains("entries[0].field_map.File")
            && e.contains("`/file/nope` is not a writable canonical field"),
        "{e}"
    );
    let e = load_error(&GOOD_ENTRY.replace("/process/pid", "/seq"));
    assert!(e.contains("`/seq` is not a writable"), "{e}");
}

#[test]
fn unknown_signer_fields_are_rejected() {
    let entry = format!(
        "{GOOD_ENTRY}    signatures:\n      source_event_id: 2\n      count_field: C\n      index_field: I\n      field_map:\n        P: nope\n"
    );
    let e = load_error(&entry);
    assert!(
        e.contains("signatures.field_map.P") && e.contains("not a writable signer field"),
        "{e}"
    );
}

#[test]
fn unknown_keys_types_and_versions_are_rejected() {
    assert!(load_error(&GOOD_ENTRY.replace("action:", "verb:")).contains("unknown field"));
    assert!(
        load_error(&GOOD_ENTRY.replace("exec.decision", "exec.nope"))
            .contains("unknown event type")
    );
    assert!(
        load_error(&GOOD_ENTRY.replace("outcome: blocked", "outcome: maybe"))
            .contains("unknown variant")
    );
    let v2 = file_with(GOOD_ENTRY).replace("schema_version: 1.0.0", "schema_version: 2.0.0");
    assert!(
        MappingSet::from_yaml("t.yaml", &v2)
            .unwrap_err()
            .to_string()
            .contains("targets event schema 2.0.0")
    );
    let newer = file_with(GOOD_ENTRY).replace("schema_version: 1.0.0", "schema_version: 1.3.0");
    assert!(MappingSet::from_yaml("t.yaml", &newer).is_err());
    let bare = file_with(GOOD_ENTRY)
        .replace("schema_version: 1.0.0", "schema_version: 1.1.0")
        .replace("os_code_integrity", "third_party");
    assert!(
        MappingSet::from_yaml("t.yaml", &bare)
            .unwrap_err()
            .to_string()
            .contains("third_party:<format>")
    );
    let bad_format = bare.replace("third_party", "third_party:Bad-Name");
    assert!(MappingSet::from_yaml("t.yaml", &bad_format).is_err());
    let old = file_with(GOOD_ENTRY).replace("os_code_integrity", "third_party:generic");
    assert!(
        MappingSet::from_yaml("t.yaml", &old)
            .unwrap_err()
            .to_string()
            .contains("need schema version 1.1.0")
    );
}

#[test]
fn strict_yaml_rules_apply() {
    let dup =
        file_with(&GOOD_ENTRY.replace("      Pid: /process/pid\n", "      File: /process/pid\n"));
    assert!(
        MappingSet::from_yaml("t.yaml", &dup)
            .unwrap_err()
            .to_string()
            .to_lowercase()
            .contains("duplicate")
    );
    let alias = file_with(&GOOD_ENTRY.replace("outcome: blocked", "outcome: &x blocked"));
    assert!(MappingSet::from_yaml("t.yaml", &alias).is_err());
}

#[test]
fn required_field_sets_must_be_fillable() {
    let entry = GOOD_ENTRY.replace(
        "      File: /file/path\n",
        "      Path: /native/policy_name\n",
    );
    let e = load_error(&entry);
    assert!(e.contains("requires the `file` field set"), "{e}");
}

#[test]
fn decisions_need_the_ism_0585_fields() {
    let no_subject = GOOD_ENTRY.replace("      Pid: /process/pid\n", "");
    assert!(load_error(&no_subject).contains("must map its subject"));
    let no_object = GOOD_ENTRY.replace("/file/path", "/file/hashes/sha256");
    assert!(load_error(&no_object).contains("the name of its object"));
}

#[test]
fn a_target_is_filled_once() {
    let entry = GOOD_ENTRY.replace(
        "      Pid: /process/pid\n",
        "      Pid: /process/pid\n      Other: /file/path\n",
    );
    assert!(load_error(&entry).contains("filled by more than one source field"));
    let list = GOOD_ENTRY.replace("File: /file/path", "File: [/file/path, /file/path]");
    assert!(load_error(&list).contains("filled by more than one source field"));
}

#[test]
fn when_rules_must_leave_every_entry_reachable() {
    let two_fallbacks = format!("{GOOD_ENTRY}{GOOD_ENTRY}");
    assert!(load_error(&two_fallbacks).contains("unreachable"));
    let empty_when = GOOD_ENTRY.replace(
        "    canonical_type:",
        "    when:\n      field: X\n    canonical_type:",
    );
    assert!(load_error(&empty_when).contains("at least one"));
    let both = GOOD_ENTRY.replace(
        "    canonical_type:",
        "    when:\n      field: X\n      present: true\n      equals: [a]\n    canonical_type:",
    );
    assert!(load_error(&both).contains("either `present: true`"));
}

#[test]
fn a_source_event_id_is_mapped_by_one_file() {
    let mut set = MappingSet::from_yaml("a.yaml", &file_with(GOOD_ENTRY)).unwrap();
    let e = set.add_yaml("b.yaml", &file_with(GOOD_ENTRY)).unwrap_err();
    assert!(
        e.to_string().contains("already mapped by another file"),
        "{e}"
    );
}

#[test]
fn every_builtin_file_loads() {
    let set = MappingSet::builtin().unwrap();
    for source in [
        SourceKind::OsCodeIntegrity,
        SourceKind::OsLegacyRuleCollection,
        SourceKind::OsSecurity,
        SourceKind::OsPowershell,
    ] {
        assert!(!set.event_ids(source).is_empty(), "{}", source.as_str());
    }
    assert!(set.event_ids(SourceKind::ThirdParty).is_empty());
    for (format, _, _) in THIRD_PARTY {
        let set = MappingSet::third_party(format).unwrap().unwrap();
        assert!(
            !set.event_ids(SourceKind::ThirdParty).is_empty(),
            "{format}"
        );
    }
    assert!(MappingSet::third_party("nope").unwrap().is_none());
}

// ---------------------------------------------------------------- 1.1 lints

/// A one-entry 1.1 file around `entry`, with a file-level `head`.
fn file_11(head: &str, entry: &str) -> String {
    format!("schema_version: 1.1.0\nsource: os_security\n{head}entries:\n{entry}")
}

const GOOD_11: &str = "  - source_event_id: 1
    canonical_type: exec.decision
    action: execute
    outcome: blocked
    description: Blocked.
    field_map:
      File: /file/path
      Pid: /process/pid
";

fn load_error_11(head: &str, entry: &str) -> String {
    MappingSet::from_yaml("t.yaml", &file_11(head, entry))
        .unwrap_err()
        .to_string()
}

#[test]
fn a_file_cannot_use_newer_parts_than_its_version() {
    let network = format!("{GOOD_ENTRY}      Host: /network/remote_hostname\n");
    let e = load_error(&network);
    assert!(
        e.contains("entries[0].field_map.Host") && e.contains("new in schema version 1.1.0"),
        "{e}"
    );
    let new_type = GOOD_ENTRY
        .replace("exec.decision", "process.created")
        .replace("File: /file/path", "File: /process/image_path");
    assert!(load_error(&new_type).contains("entries[0].canonical_type"));
    let constant = format!("{GOOD_ENTRY}    set:\n      /script/text: x\n");
    assert!(load_error(&constant).contains("entries[0].set./script/text"));
    // The same entries load at 1.1.
    let ok = file_11(
        "",
        &format!("{GOOD_11}      Host: /network/remote_hostname\n"),
    );
    assert!(MappingSet::from_yaml("t.yaml", &ok).is_ok());
}

#[test]
fn value_tables_are_checked_and_used() {
    let head = "value_maps:\n  lt:\n    \"2\": interactive\n    \"10\": remote_interactive\n";
    let entry = format!("{GOOD_11}      Type:\n        to: /user/logon_type\n        values: lt\n");
    let set = MappingSet::from_yaml("t.yaml", &file_11(head, &entry)).unwrap();
    let map = |t: &str| {
        set.map(
            SourceKind::OsSecurity,
            &record(1, &[("File", "a"), ("Pid", "1"), ("Type", t)]),
            &[],
            &envelope(),
        )
        .unwrap()
    };
    let mapped = map("10");
    assert_eq!(
        mapped.event.user.unwrap().logon_type,
        Some(crate::events::LogonType::RemoteInteractive)
    );
    let mapped = map("0");
    assert_eq!(mapped.dropped[0].field, "Type");
    assert!(mapped.event.user.is_none());
    // A table value the target cannot hold.
    let bad = head.replace("remote_interactive", "remote");
    let e = load_error_11(&bad, &entry);
    assert!(e.contains("maps `10` to `remote`"), "{e}");
    // Unknown and unused tables.
    let unknown = entry.replace("values: lt", "values: nope");
    assert!(load_error_11(head, &unknown).contains("no value table `nope`"));
    assert!(load_error_11(head, GOOD_11).contains("value_maps.lt: is not used"));
    assert!(load_error_11("value_maps:\n  e: {}\n", GOOD_11).contains("1 to 256 entries"));
}

#[test]
fn enum_sets_split_and_sort() {
    let head = "value_maps:\n  c:\n    \"%%8448\": success_removed\n    \"%%8449\": success_added\n    \"%%8451\": failure_added\n";
    let entry = format!(
        "{GOOD_11}      Changes:\n        to: /audit_policy/changes\n        values: c\n        split: \",\"\n"
    );
    let set = MappingSet::from_yaml("t.yaml", &file_11(head, &entry)).unwrap();
    let map = |v: &str| {
        set.map(
            SourceKind::OsSecurity,
            &record(1, &[("File", "a"), ("Pid", "1"), ("Changes", v)]),
            &[],
            &envelope(),
        )
        .unwrap()
    };
    let event = map("%%8451, %%8449,%%8449").event;
    assert_eq!(
        event.audit_policy.unwrap().changes.as_slice(),
        [
            crate::events::AuditPolicyChange::SuccessAdded,
            crate::events::AuditPolicyChange::FailureAdded
        ]
    );
    let mapped = map("%%8449, %%8452");
    assert_eq!(mapped.dropped[0].field, "Changes");
    assert!(mapped.event.audit_policy.is_none());
    // `split` only with a set, and a set only with `split`.
    let no_split = entry.replace("        split: \",\"\n", "");
    assert!(load_error_11(head, &no_split).contains("is a set exactly when"));
    let split_scalar = format!(
        "{GOOD_11}      Kind:\n        to: /process/integrity_level\n        split: \",\"\n"
    );
    assert!(load_error_11("", &split_scalar).contains("is a set exactly when"));
}

#[test]
fn constants_are_read_as_their_target() {
    let entry = format!(
        "{GOOD_11}    set:\n      /script/kind: powershell\n      /script/inline: \"true\"\n      /network/remote_port: \"443\"\n"
    );
    let set = MappingSet::from_yaml("t.yaml", &file_11("", &entry)).unwrap();
    let event = set
        .map(
            SourceKind::OsSecurity,
            &record(1, &[("File", "a"), ("Pid", "1")]),
            &[],
            &envelope(),
        )
        .unwrap()
        .event;
    assert_eq!(event.network.unwrap().remote_port, Some(443));
    assert_eq!(
        event.script.unwrap().kind,
        Some(crate::events::ScriptKind::Powershell)
    );
    for (constant, why) in [
        ("/script/kind: nope", "not a value"),
        ("/network/remote_port: \"70000\"", "not a value"),
        ("/file/path: x", "filled more than once"),
        ("/seq: \"1\"", "not a writable"),
        ("/script/inline: \"false\"", "not a value"),
    ] {
        let e = load_error_11("", &format!("{GOOD_11}    set:\n      {constant}\n"));
        assert!(e.contains(why), "{constant}: {e}");
    }
}

#[test]
fn absent_values_are_left_out() {
    let head = "absent_values: [\"-\", \"S-1-0-0\"]\n";
    let entry = format!(
        "{GOOD_11}      Sid: /user/sid\n      Kind:\n        to: /process/integrity_level\n"
    );
    let set = MappingSet::from_yaml("t.yaml", &file_11(head, &entry)).unwrap();
    let mapped = set
        .map(
            SourceKind::OsSecurity,
            &record(
                1,
                &[
                    ("File", "a"),
                    ("Pid", "1"),
                    ("Sid", "S-1-0-0"),
                    ("Kind", "-"),
                ],
            ),
            &[],
            &envelope(),
        )
        .unwrap();
    assert!(mapped.event.user.is_none());
    assert!(mapped.dropped.is_empty());
    assert!(load_error_11("absent_values: [\"\"]\n", GOOD_11).contains("absent_values[0]"));
    assert!(load_error_11("absent_values: [a, a]\n", GOOD_11).contains("absent_values[1]"));
    let constant = format!("{GOOD_11}    set:\n      /user/name: \"-\"\n");
    assert!(load_error_11("absent_values: [\"-\"]\n", &constant).contains("absent values"));
}

#[test]
fn when_present_selects_on_a_value() {
    let entries = format!(
        "{}{}",
        GOOD_11.replace(
            "    canonical_type:",
            "    when:\n      field: Path\n      present: true\n    canonical_type:"
        ),
        GOOD_11.replace("exec.decision", "library.decision")
    );
    let set =
        MappingSet::from_yaml("t.yaml", &file_11("absent_values: [\"-\"]\n", &entries)).unwrap();
    let ty = |path: &str| {
        set.map(
            SourceKind::OsSecurity,
            &record(1, &[("File", "a"), ("Pid", "1"), ("Path", path)]),
            &[],
            &envelope(),
        )
        .unwrap()
        .event
        .event_type
    };
    assert_eq!(ty("C:\\a.ps1"), EventType::ExecDecision);
    assert_eq!(ty(""), EventType::LibraryDecision);
    assert_eq!(ty("-"), EventType::LibraryDecision);
    // A later condition on the same field after `present` is unreachable.
    let shadowed = format!(
        "{}{}",
        GOOD_11.replace(
            "    canonical_type:",
            "    when:\n      field: Path\n      present: true\n    canonical_type:"
        ),
        GOOD_11.replace(
            "    canonical_type:",
            "    when:\n      field: Path\n      equals: [x]\n    canonical_type:"
        )
    );
    assert!(load_error_11("", &shadowed).contains("every value of `Path`"));
}

#[test]
fn first_signer_targets_fill_one_signer() {
    let entry = format!(
        "{GOOD_11}      Pub: /file/signers/0/publisher\n      Iss: /file/signers/0/issuer\n"
    );
    let set = MappingSet::from_yaml("t.yaml", &file_11("", &entry)).unwrap();
    let event = set
        .map(
            SourceKind::OsSecurity,
            &record(
                1,
                &[("File", "a"), ("Pid", "1"), ("Pub", "P"), ("Iss", "I")],
            ),
            &[],
            &envelope(),
        )
        .unwrap()
        .event;
    let signers = event.file.unwrap().signers;
    assert_eq!(signers.len(), 1);
    assert_eq!(signers.as_slice()[0].issuer.as_ref().unwrap().as_str(), "I");
    // Not together with signature records.
    let both = format!(
        "{entry}    signatures:\n      source_event_id: 2\n      count_field: C\n      index_field: I\n      field_map:\n        P: publisher\n"
    );
    assert!(load_error_11("", &both).contains("cannot also fill `/file/signers`"));
}

#[test]
fn third_party_events_carry_their_format() {
    let text = file_11("", GOOD_11).replace("os_security", "third_party:legacy_csv");
    let mut set = MappingSet::from_yaml("t.yaml", &text).unwrap();
    let event = set
        .map(
            SourceKind::ThirdParty,
            &record(1, &[("File", "a"), ("Pid", "1")]),
            &[],
            &envelope(),
        )
        .unwrap()
        .event;
    let source = event.source.unwrap();
    assert_eq!(source.kind, SourceKind::ThirdParty);
    assert_eq!(source.format.unwrap().as_str(), "legacy_csv");
    // One format per set.
    let other = file_11(
        "",
        &GOOD_11.replace("source_event_id: 1", "source_event_id: 2"),
    )
    .replace("os_security", "third_party:other");
    assert!(
        set.add_yaml("u.yaml", &other)
            .unwrap_err()
            .to_string()
            .contains("already translates")
    );
}

#[test]
fn subject_lint_matches_the_ism_0585_checklist() {
    // Only fields that `ism_0585_gaps` accepts count as the subject.
    for weak in [
        "/user/logon_id",
        "/user/domain",
        "/process/cmdline",
        "/process/owner_sid",
    ] {
        let entry = GOOD_ENTRY.replace("/process/pid", weak);
        assert!(
            load_error(&entry).contains("must map its subject"),
            "{weak}"
        );
    }
    for strong in ["/user/sid", "/user/name", "/process/image_path"] {
        let entry = GOOD_ENTRY.replace("/process/pid", strong);
        assert!(
            MappingSet::from_yaml("t.yaml", &file_with(&entry)).is_ok(),
            "{strong}"
        );
    }
}

#[test]
fn signatures_do_not_fill_the_file_field_set() {
    let entry = "  - source_event_id: 1
    canonical_type: exec.origin_check
    action: origin_check
    outcome: info
    description: Check.
    field_map:
      Policy: /native/policy_name
    signatures:
      source_event_id: 2
      count_field: C
      index_field: I
      field_map:
        P: publisher
";
    assert!(load_error(entry).contains("requires the `file` field set"));
}

fn when_entry(when: &str, ty: &str) -> String {
    format!(
        "  - source_event_id: 1
    when:
{when}    canonical_type: {ty}
    action: load
    outcome: blocked
    description: X.
    field_map:
      File: /file/path
      Pid: /process/pid
"
    )
}

#[test]
fn shadowed_and_empty_when_values_are_rejected() {
    let dll = "      field: Kind\n      equals: [DLL]\n";
    let first = when_entry(dll, "library.decision");
    for (second, why) in [
        (dll.to_owned(), "already matched"),
        (
            "      field: Kind\n      equals: [dll]\n".to_owned(),
            "already matched",
        ),
        (
            "      field: Kind\n      equals: [exe, Dll]\n".to_owned(),
            "already matched",
        ),
    ] {
        let text = format!("{first}{}", when_entry(&second, "exec.decision"));
        let e = MappingSet::from_yaml("t.yaml", &file_with(&text))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("entries[1].when") && e.contains(why),
            "{second}: {e}"
        );
    }
    let sys = when_entry(
        "      field: File\n      ends_with: [.sys]\n",
        "driver.decision",
    );
    let later = when_entry(
        "      field: File\n      ends_with: [driver.SYS]\n",
        "exec.decision",
    );
    assert!(MappingSet::from_yaml("t.yaml", &file_with(&format!("{sys}{later}"))).is_err());
    let exact = when_entry(
        "      field: File\n      equals: [a.sys]\n",
        "exec.decision",
    );
    assert!(MappingSet::from_yaml("t.yaml", &file_with(&format!("{sys}{exact}"))).is_err());
    // A shorter suffix after a longer one still matches other values: allowed.
    let long = when_entry(
        "      field: File\n      ends_with: [x.sys]\n",
        "driver.decision",
    );
    let short = when_entry(
        "      field: File\n      ends_with: [.sys]\n",
        "exec.decision",
    );
    assert!(MappingSet::from_yaml("t.yaml", &file_with(&format!("{long}{short}"))).is_ok());
    // Different fields cannot be compared: file order decides.
    let other = when_entry("      field: Other\n      equals: [DLL]\n", "exec.decision");
    assert!(MappingSet::from_yaml("t.yaml", &file_with(&format!("{first}{other}"))).is_ok());
    for bad in [
        "      field: Kind\n      equals: [\"\"]\n",
        "      field: Kind\n      ends_with: [\"\"]\n",
        "      field: Kind\n      equals: [a, A]\n",
    ] {
        let e = load_error(&when_entry(bad, "exec.decision"));
        assert!(e.contains("entries[0].when"), "{bad}: {e}");
    }
}

#[test]
fn a_rejected_file_leaves_the_set_unchanged() {
    let mut set = MappingSet::from_yaml(
        "a.yaml",
        &file_with(&GOOD_ENTRY.replace("source_event_id: 1", "source_event_id: 5")),
    )
    .unwrap();
    // Event 1 is new, event 5 collides: nothing from this file may be added.
    let text = file_with(&format!(
        "{GOOD_ENTRY}{}",
        GOOD_ENTRY.replace("source_event_id: 1", "source_event_id: 5")
    ));
    assert!(set.add_yaml("b.yaml", &text).is_err());
    assert_eq!(set.event_ids(SourceKind::OsCodeIntegrity), [5]);
}

#[test]
fn an_empty_field_value_never_matches_when() {
    let set = MappingSet::from_yaml(
        "t.yaml",
        &file_with(&when_entry(
            "      field: Kind\n      ends_with: [x]\n",
            "exec.decision",
        )),
    )
    .unwrap();
    let rec = record(1, &[("Kind", ""), ("File", "a"), ("Pid", "1")]);
    assert!(matches!(
        set.map(SourceKind::OsCodeIntegrity, &rec, &[], &envelope()),
        Err(MapError::Unmapped { .. })
    ));
}

#[test]
fn dropped_signer_fields_name_the_signature_index() {
    let rec = record(1, &[("File", "a"), ("Pid", "1")]);
    let mut second = sig("1", "2", "B");
    second.fields.insert("Tbs".to_owned(), "zz".to_owned());
    let mapped = good_set()
        .map(SourceKind::OsCodeIntegrity, &rec, &[second], &envelope())
        .unwrap();
    assert_eq!(
        mapped
            .dropped
            .iter()
            .map(|d| d.field.as_str())
            .collect::<Vec<_>>(),
        ["Tbs[1]"]
    );
}

// ---------------------------------------------------------------- mapping

fn good_set() -> MappingSet {
    let entry = format!(
        "{GOOD_ENTRY}      Hash: /file/hashes/sha256\n      Level: /native/validated_signing_level\n    signatures:\n      source_event_id: 2\n      count_field: Count\n      index_field: Index\n      field_map:\n        Publisher: publisher\n        Tbs: tbs_hash\n"
    );
    MappingSet::from_yaml("t.yaml", &file_with(&entry)).unwrap()
}

#[test]
fn a_record_maps_to_a_valid_event() {
    let rec = record(
        1,
        &[
            ("File", "C:\\a.exe"),
            ("Pid", "42"),
            ("Hash", &"AA".repeat(32)),
            ("Ignored", "x"),
        ],
    );
    let mapped = good_set()
        .map(SourceKind::OsCodeIntegrity, &rec, &[], &envelope())
        .unwrap();
    let e = &mapped.event;
    assert_eq!(e.event_type, EventType::ExecDecision);
    assert_eq!(e.category, Category::Execution);
    assert_eq!(e.ts.to_string(), "2026-11-24T03:15:22.123456Z");
    assert_eq!(
        e.file.as_ref().unwrap().path.as_ref().unwrap().as_str(),
        "C:\\a.exe"
    );
    assert_eq!(
        e.file.as_ref().unwrap().hashes.sha256.unwrap().to_string(),
        "aa".repeat(32)
    );
    assert_eq!(e.process.as_ref().unwrap().pid, Some(42));
    let source = e.source.as_ref().unwrap();
    assert_eq!(
        (source.kind, source.event_id, source.record_id),
        (SourceKind::OsCodeIntegrity, Some(1), Some(7))
    );
    assert!(mapped.dropped.is_empty());
    assert!(mapped.signatures_incomplete.is_none());
    assert!(e.ism_0585_gaps().is_empty());
}

#[test]
fn unusable_values_are_dropped_and_reported() {
    let rec = record(
        1,
        &[
            ("File", "C:\\a.exe"),
            ("Pid", "42"),
            ("Hash", "zz"),
            ("Level", "999"),
        ],
    );
    let mapped = good_set()
        .map(SourceKind::OsCodeIntegrity, &rec, &[], &envelope())
        .unwrap();
    let fields: Vec<&str> = mapped.dropped.iter().map(|d| d.field.as_str()).collect();
    assert_eq!(fields, ["Hash", "Level"]);
    assert!(mapped.event.file.as_ref().unwrap().hashes.sha256.is_none());
}

#[test]
fn a_record_without_its_required_fields_is_an_error() {
    let rec = record(1, &[("Pid", "42")]);
    let err = good_set()
        .map(SourceKind::OsCodeIntegrity, &rec, &[], &envelope())
        .unwrap_err();
    assert!(
        matches!(err, MapError::Invalid(ref errors) if errors[0].path == "/file"),
        "{err}"
    );
}

#[test]
fn unmapped_ids_and_oversized_records_are_errors() {
    let set = good_set();
    let err = set
        .map(
            SourceKind::OsCodeIntegrity,
            &record(99, &[]),
            &[],
            &envelope(),
        )
        .unwrap_err();
    assert_eq!(
        err,
        MapError::Unmapped {
            source: SourceKind::OsCodeIntegrity,
            event_id: 99
        }
    );
    let err = set
        .map(
            SourceKind::OsLegacyRuleCollection,
            &record(1, &[]),
            &[],
            &envelope(),
        )
        .unwrap_err();
    assert!(matches!(err, MapError::Unmapped { .. }));
    let mut big = record(1, &[("File", "a"), ("Pid", "1")]);
    for i in 0..MAX_RECORD_FIELDS {
        big.fields.insert(format!("f{i}"), String::new());
    }
    assert_eq!(
        set.map(SourceKind::OsCodeIntegrity, &big, &[], &envelope())
            .unwrap_err(),
        MapError::TooManyFields
    );
}

#[test]
fn the_agent_owns_the_chain_fields() {
    let mut env = envelope();
    env.seq = 9;
    env.prev_hash = Some("11".repeat(32).parse().unwrap());
    let rec = record(
        1,
        &[("File", "a"), ("Pid", "1"), ("seq", "0"), ("prev_hash", "")],
    );
    let event = good_set()
        .map(SourceKind::OsCodeIntegrity, &rec, &[], &env)
        .unwrap()
        .event;
    assert_eq!(event.seq, 9);
    assert_eq!(event.prev_hash, env.prev_hash);
    // A broken envelope is caught by validation.
    env.prev_hash = None;
    let err = good_set()
        .map(SourceKind::OsCodeIntegrity, &rec, &[], &env)
        .unwrap_err();
    assert!(matches!(err, MapError::Invalid(_)));
}

fn sig(index: &str, count: &str, publisher: &str) -> Record {
    record(
        2,
        &[
            ("Index", index),
            ("Count", count),
            ("Publisher", publisher),
            ("Tbs", "AB12"),
        ],
    )
}

#[test]
fn signatures_are_ordered_by_index() {
    let rec = record(1, &[("File", "a"), ("Pid", "1")]);
    let sigs = [sig("1", "2", "Second"), sig("0", "2", "First")];
    let mapped = good_set()
        .map(SourceKind::OsCodeIntegrity, &rec, &sigs, &envelope())
        .unwrap();
    let signers = mapped.event.file.unwrap().signers;
    let names: Vec<&str> = signers
        .as_slice()
        .iter()
        .map(|s| s.publisher.as_ref().unwrap().as_str())
        .collect();
    assert_eq!(names, ["First", "Second"]);
    assert_eq!(
        signers.as_slice()[0].tbs_hash.as_ref().unwrap().to_string(),
        "ab12"
    );
    assert!(mapped.signatures_incomplete.is_none());
}

#[test]
fn missing_signatures_are_reported_not_hidden() {
    let rec = record(1, &[("File", "a"), ("Pid", "1")]);
    let mapped = good_set()
        .map(
            SourceKind::OsCodeIntegrity,
            &rec,
            &[sig("0", "3", "Only")],
            &envelope(),
        )
        .unwrap();
    assert_eq!(mapped.signatures_incomplete, Some((1, 3)));
}

#[test]
fn an_unsigned_file_has_no_signers() {
    let rec = record(1, &[("File", "a"), ("Pid", "1")]);
    let unsigned = record(2, &[("Count", "0"), ("Index", "0")]);
    let mapped = good_set()
        .map(SourceKind::OsCodeIntegrity, &rec, &[unsigned], &envelope())
        .unwrap();
    assert!(mapped.event.file.unwrap().signers.is_empty());
    assert!(mapped.signatures_incomplete.is_none());
}

#[test]
fn inconsistent_signatures_are_rejected() {
    let set = good_set();
    let rec = record(1, &[("File", "a"), ("Pid", "1")]);
    let map = |sigs: &[Record]| set.map(SourceKind::OsCodeIntegrity, &rec, sigs, &envelope());
    let mut wrong_id = sig("1", "1", "A");
    wrong_id.event_id = 3;
    let mut wrong_activity = sig("1", "1", "A");
    wrong_activity.activity_id = Some("00000000-0000-0000-0000-000000000001".parse().unwrap());
    let mut wide = sig("0", "1", "A");
    for i in 0..MAX_RECORD_FIELDS {
        wide.fields.insert(format!("f{i}"), String::new());
    }
    let unsigned = || record(2, &[("Count", "0"), ("Index", "0")]);
    let many: Vec<Record> = (0..65).map(|i| sig(&i.to_string(), "65", "A")).collect();
    for (sigs, why) in [
        (vec![wrong_id], "expected event 2"),
        (vec![wrong_activity], "activity ID"),
        (
            vec![sig("0", "2", "A"), sig("0", "2", "B")],
            "appears twice",
        ),
        (vec![sig("0", "1", "A"), sig("1", "2", "B")], "disagree"),
        (
            vec![sig("0", "1", "A"), sig("1", "1", "B")],
            "not below the count",
        ),
        (vec![sig("5", "2", "A")], "not below the count"),
        (vec![sig("0", "65", "A")], "more than 64"),
        (many, "more than the 64"),
        (vec![sig("x", "1", "A")], "not a number"),
        (vec![unsigned(), unsigned()], "exactly one record"),
        (vec![wide], "more than 256 fields"),
    ] {
        let err = map(&sigs).unwrap_err();
        assert!(
            matches!(&err, MapError::BadSignatures(w) if w.contains(why)),
            "{why}: {err}"
        );
    }
    let mut no_activity = rec.clone();
    no_activity.activity_id = None;
    let err = set
        .map(
            SourceKind::OsCodeIntegrity,
            &no_activity,
            &[sig("1", "1", "A")],
            &envelope(),
        )
        .unwrap_err();
    assert!(matches!(err, MapError::BadSignatures(_)));
}

#[test]
fn when_selects_the_entry() {
    let text = file_with(
        "  - source_event_id: 1
    when:
      field: Kind
      equals: [DLL]
    canonical_type: library.decision
    action: load
    outcome: blocked
    description: Library.
    field_map:
      File: /file/path
      Pid: /process/pid
  - source_event_id: 1
    when:
      field: File
      ends_with: [.SYS]
    canonical_type: driver.decision
    action: load
    outcome: blocked
    description: Driver.
    field_map:
      File: /file/path
      Pid: /process/pid
",
    );
    let set = MappingSet::from_yaml("t.yaml", &text).unwrap();
    let map = |fields: &[(&str, &str)]| {
        set.map(
            SourceKind::OsCodeIntegrity,
            &record(1, fields),
            &[],
            &envelope(),
        )
    };
    assert_eq!(
        map(&[("Kind", "dll"), ("File", "a"), ("Pid", "1")])
            .unwrap()
            .event
            .event_type,
        EventType::LibraryDecision
    );
    assert_eq!(
        map(&[("File", "C:\\x.sys"), ("Pid", "1")])
            .unwrap()
            .event
            .event_type,
        EventType::DriverDecision
    );
    // No fallback: nothing matches.
    assert!(matches!(
        map(&[("File", "a.exe"), ("Pid", "1")]),
        Err(MapError::Unmapped { .. })
    ));
}

#[test]
fn empty_and_absent_values_are_never_dropped() {
    let head = "absent_values: [\"-\"]\nvalue_maps:\n  lt:\n    \"2\": interactive\n";
    let entry = format!(
        "{GOOD_11}      Type:\n        to: /user/logon_type\n        values: lt\n    signatures:\n      source_event_id: 2\n      count_field: Count\n      index_field: Index\n      field_map:\n        Publisher: publisher\n        Tbs: tbs_hash\n"
    );
    let set = MappingSet::from_yaml("t.yaml", &file_11(head, &entry)).unwrap();
    for empty in ["", "-"] {
        let rec = record(1, &[("File", "a"), ("Pid", "1"), ("Type", empty)]);
        let signer = record(
            2,
            &[
                ("Count", "1"),
                ("Index", "0"),
                ("Publisher", "P"),
                ("Tbs", empty),
            ],
        );
        let mapped = set
            .map(SourceKind::OsSecurity, &rec, &[signer], &envelope())
            .unwrap();
        assert!(mapped.dropped.is_empty(), "{empty:?}: {:?}", mapped.dropped);
        assert!(mapped.event.user.is_none());
        let signers = mapped.event.file.unwrap().signers;
        assert!(signers.as_slice()[0].tbs_hash.is_none());
    }
}

#[test]
fn when_values_and_absent_values_are_checked() {
    let when = GOOD_11.replace(
        "    canonical_type:",
        "    when:\n      field: X\n      equals: [\"-\"]\n    canonical_type:",
    );
    assert!(load_error_11("absent_values: [\"-\"]\n", &when).contains("never matches"));
    let many: Vec<String> = (0..17).map(|i| format!("\"v{i}\"")).collect();
    let head = format!("absent_values: [{}]\n", many.join(", "));
    assert!(load_error_11(&head, GOOD_11).contains("more than 16"));
}
