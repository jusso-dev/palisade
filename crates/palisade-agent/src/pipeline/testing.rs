//! Test helpers for the pipeline.

use palisade_proto::events::{
    Description, Event, EventType, File, Host, HostId, LongText, Outcome, Severity, TenantId,
    Timestamp, Uuid7,
};

/// A fixed UUIDv7 ending in `n`.
pub fn uuid(n: u8) -> Uuid7 {
    let mut b = [0u8; 16];
    b[6] = 0x70;
    b[8] = 0x80;
    b[15] = n;
    Uuid7::from_bytes(b).unwrap()
}

/// 2023-11-14T22:13:20Z, plus `secs`.
pub fn at(secs: i64) -> Timestamp {
    Timestamp::from_unix_micros(1_700_000_000_000_000 + secs * 1_000_000).unwrap()
}

/// A valid event of `ty` with `outcome`, at [`at`]`(secs)`, with a file
/// for the types that need one.
pub fn event(ty: EventType, outcome: Outcome, secs: i64) -> Event {
    let mut e: Event = serde_json::from_value(serde_json::json!({
        "schema_version": palisade_proto::events::CURRENT.to_string(),
        "event_id": uuid(1).to_string(),
        "event_type": ty.as_str(),
        "category": serde_json::to_value(ty.category()).unwrap(),
        "action": "execute",
        "outcome": serde_json::to_value(outcome).unwrap(),
        "severity": 3,
        "description": "A test event.",
        "ts": at(secs).to_string(),
        "clock_synced": true,
        "tenant_id": uuid(2).to_string(),
        "host": { "id": uuid(3).to_string() },
        "seq": 0
    }))
    .unwrap();
    for &set in ty.required() {
        use palisade_proto::events::FieldSet;
        match set {
            FieldSet::File => {
                e.file = Some(File {
                    path: Some(LongText::new("C:\\a.exe").unwrap()),
                    ..File::default()
                });
            }
            FieldSet::Agent => e.agent = Some(Default::default()),
            FieldSet::Native => e.native = Some(Default::default()),
            FieldSet::Admin => e.admin = Some(Default::default()),
            FieldSet::Policy => e.policy = Some(Default::default()),
            FieldSet::Process => e.process = Some(Default::default()),
            FieldSet::Script => {
                e.script = Some(palisade_proto::events::Script {
                    inline: true,
                    ..Default::default()
                });
            }
            other => panic!("add a field set for {other:?}"),
        }
    }
    e.severity = Severity::new(3).unwrap();
    e.description = Description::new("A test event.").unwrap();
    e.host = Host {
        id: HostId(uuid(3)),
        ..e.host
    };
    e.tenant_id = TenantId(uuid(2));
    e
}

/// `event` for a file at `path`.
pub fn exec(outcome: Outcome, secs: i64, path: &str) -> Event {
    let mut e = event(EventType::ExecDecision, outcome, secs);
    if let Some(f) = e.file.as_mut() {
        f.path = Some(LongText::new(path).unwrap());
    }
    e
}
