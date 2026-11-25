//! Snapshot tests of event JSON (#25), with `insta`.
//!
//! Each case builds an event from the fields a producer sets, and compares
//! its canonical JSON (`Event::to_canonical_json`: compact, fields in schema
//! order) with a reviewed snapshot in `tests/snapshots/events/`, byte for
//! byte. A change to field names, field order, optional fields or enum
//! spellings shows up as a snapshot diff in the PR, so a wire change is
//! never silent. A second snapshot per event holds the same JSON
//! pretty-printed, with sorted keys, so a reviewer can read the diff.
//!
//! After a deliberate change, review and accept the new snapshots with
//! `cargo insta review` (or rerun with `INSTA_UPDATE=always` and read the
//! diff). CI runs `cargo insta test --check` (docs/testing.md#snapshot-tests).

#![allow(clippy::unwrap_used)]

use palisade_proto::events::Event;

const UUID: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f";

/// The fields every event has, then `extra`.
fn event(extra: serde_json::Value) -> Event {
    let mut value = serde_json::json!({
        "schema_version": "1.1.0",
        "event_id": UUID,
        "ts": "2026-11-24T03:15:22.123456Z",
        "clock_synced": true,
        "tenant_id": UUID,
        "host": { "id": UUID, "name": "WS-0001" },
        "seq": 0
    });
    for (k, v) in extra.as_object().unwrap() {
        value[k] = v.clone();
    }
    let event = Event::from_json(&value.to_string()).unwrap();
    event.validate().unwrap();
    event
}

/// Snapshots `event` under `name`: the canonical bytes, and a readable
/// copy.
fn snapshot(name: &str, event: &Event) {
    let canonical = event.to_canonical_json().unwrap();
    let readable: serde_json::Value = serde_json::from_str(&canonical).unwrap();
    settings().bind(|| {
        insta::assert_snapshot!(format!("{name}_canonical"), canonical);
        insta::assert_json_snapshot!(name, readable);
    });
}

fn settings() -> insta::Settings {
    let mut s = insta::Settings::clone_current();
    s.set_prepend_module_to_snapshot(false);
    s.set_omit_expression(true);
    s.set_snapshot_path("snapshots/events");
    s
}

#[test]
fn agent_started() {
    let e = event(serde_json::json!({
        "event_type": "agent.started",
        "category": "agent",
        "action": "start",
        "outcome": "info",
        "severity": 2,
        "description": "The agent started."
    }));
    snapshot("agent_started", &e);
}

#[test]
fn an_executable_blocked_by_a_rule() {
    let e = event(serde_json::json!({
        "event_type": "exec.decision",
        "category": "execution",
        "action": "execute",
        "outcome": "blocked",
        "severity": 6,
        "mode": "enforce",
        "description": "An executable was blocked.",
        "user": { "sid": "S-1-5-21-1111111111-2222222222-3333333333-1001", "name": "alice" },
        "process": { "pid": 4412, "image_path": "C:\\Windows\\explorer.exe" },
        "file": {
            "path": "C:\\Users\\alice\\Downloads\\tool.exe",
            "size": 102400,
            "hashes": { "sha256": "ab".repeat(32) },
            "signers": [{ "publisher": "Example Software Ltd" }],
            "version_info": { "original_filename": "tool.exe", "file_version": "1.2.3.4" }
        }
    }));
    snapshot("exec_blocked", &e);
}
