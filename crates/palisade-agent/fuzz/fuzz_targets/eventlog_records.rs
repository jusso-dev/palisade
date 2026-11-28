//! Fuzzes the event-log record decoder and the ingest chain behind it
//! (#58). The input is rendered event XML, as the OS event log hands it
//! over; the first byte picks the channel's source. No input may panic,
//! and every event the chain emits must be a valid canonical event.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use palisade_agent::eventlog::Source;
use palisade_agent::eventlog::decode::decode;
use palisade_agent::eventlog::ingest::{Context, EnvelopeSource, EventSink, Ingest};
use palisade_proto::events::{Event, Host, HostId, Labels, TenantId, Uuid7};
use palisade_proto::mapping::{Envelope, MappingSet};

fn mappings() -> &'static MappingSet {
    static SET: OnceLock<MappingSet> = OnceLock::new();
    SET.get_or_init(|| MappingSet::builtin().unwrap())
}

fn id(n: u8) -> Uuid7 {
    let mut b = [n; 16];
    b[6] = 0x70;
    b[8] = 0x80;
    Uuid7::from_bytes(b).unwrap()
}

struct Envelopes;
impl EnvelopeSource for Envelopes {
    fn next(&mut self) -> Envelope {
        Envelope {
            event_id: id(1),
            tenant_id: TenantId(id(2)),
            host: Host {
                id: HostId(id(3)),
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
}

struct Check;
impl EventSink for Check {
    fn offer(&mut self, event: Event) -> bool {
        assert!(event.validate().is_ok());
        true
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&pick, xml)) = data.split_first() else {
        return;
    };
    let source = match pick % 3 {
        0 => Source::CodeIntegrity,
        1 => Source::RuleCollection,
        _ => Source::PowerShell,
    };
    let _ = decode(xml);
    let mut ingest = Ingest::with(mappings().clone(), 1000, 10);
    let mut ctx = Context {
        now: 0,
        tree: None,
        envelopes: &mut Envelopes,
        sink: &mut Check,
    };
    ingest.push(source, xml, &mut ctx);
    ingest.flush(&mut ctx);
});
