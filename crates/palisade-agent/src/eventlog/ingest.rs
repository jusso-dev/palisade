//! The event-log ingest chain (#58).
//!
//! Each rendered record goes through these steps:
//!
//! 1. [`decode`](super::decode::decode): XML to a mapping `Record`. A
//!    record that does not decode is counted.
//! 2. The [`RateLimiter`]: at most 2,000 records a second by default. Over
//!    the rate, records are dropped and counted, never silently.
//! 3. The [`Correlator`] for its source: decisions wait for their
//!    per-signature records.
//! 4. The policy [`PolicyInventory`] sees every activation.
//! 5. `palisade_proto::mapping`: the canonical event. A record with no
//!    mapping is counted as unmapped; one that fails to map is counted.
//! 6. If the event names a process (`process.pid`) and the #59 process
//!    tree knew a process with that ID at the record's time, its process
//!    key, parent, grandparent and command line are added. The OS log's
//!    own process name is kept.
//! 7. The event goes to an [`EventSink`]; a refused event is counted.
//!
//! The canonical envelope (event ID, sequence number, hash chain) belongs
//! to the event pipeline (#63, #197). Until it exists, an
//! [`EnvelopeSource`] supplies it.

#![forbid(unsafe_code)]

use palisade_core::platform::UtcTime;
use palisade_proto::events::{Event, Process, SourceKind};
use palisade_proto::mapping::{Envelope, MapError, MappingSet};

use super::Source;
use super::correlate::{
    CODE_INTEGRITY, Correlator, DEFAULT_RATE, DEFAULT_WAIT, Group, RateLimiter, SCRIPT_HOSTS,
};
use super::decode::decode;
use super::inventory::PolicyInventory;
use crate::telemetry::output::process_fields;
use crate::telemetry::tree::ProcessTree;

/// Supplies the envelope of each new event.
pub trait EnvelopeSource {
    /// The envelope for the next event.
    fn next(&mut self) -> Envelope;
}

/// Where mapped events go. Implementations must not block.
pub trait EventSink {
    /// Offers an event; `false` if it was not accepted.
    fn offer(&mut self, event: Event) -> bool;
}

/// What the chain has counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IngestStats {
    /// Records that did not decode.
    pub undecoded: u64,
    /// Records over the rate limit.
    pub rate_limited: u64,
    /// Records with no mapping for their event ID.
    pub unmapped: u64,
    /// Records whose mapping failed.
    pub map_failed: u64,
    /// Events the sink refused.
    pub sink_refused: u64,
    /// Events emitted.
    pub emitted: u64,
    /// Events emitted with signature records missing.
    pub incomplete: u64,
}

/// The ingest chain.
pub struct Ingest {
    mappings: MappingSet,
    limiter: RateLimiter,
    code_integrity: Correlator,
    script_hosts: Correlator,
    inventory: PolicyInventory,
    stats: IngestStats,
}

impl std::fmt::Debug for Ingest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ingest")
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

/// The context one record is ingested in.
pub struct Context<'a> {
    /// The monotonic time, in microseconds.
    pub now: u64,
    /// The process tree, if the process monitor runs.
    pub tree: Option<&'a ProcessTree>,
    /// The envelope source.
    pub envelopes: &'a mut dyn EnvelopeSource,
    /// The sink.
    pub sink: &'a mut dyn EventSink,
}

impl Ingest {
    /// A chain with the shipped mappings, the default rate and the default
    /// correlation wait.
    ///
    /// # Errors
    ///
    /// The shipped mappings do not load (a build defect; CI loads them).
    pub fn new() -> Result<Self, palisade_proto::mapping::LoadError> {
        Ok(Self::with(
            MappingSet::builtin()?,
            DEFAULT_RATE,
            DEFAULT_WAIT,
        ))
    }

    /// A chain with `mappings`, `rate` records a second and a correlation
    /// wait of `wait` microseconds.
    #[must_use]
    pub fn with(mappings: MappingSet, rate: u32, wait: u64) -> Self {
        Self {
            mappings,
            limiter: RateLimiter::new(rate),
            code_integrity: Correlator::new(CODE_INTEGRITY, wait),
            script_hosts: Correlator::new(SCRIPT_HOSTS, wait),
            inventory: PolicyInventory::default(),
            stats: IngestStats::default(),
        }
    }

    /// What has been counted.
    #[must_use]
    pub const fn stats(&self) -> IngestStats {
        let mut s = self.stats;
        s.rate_limited = self.limiter.dropped();
        s
    }

    /// The policy inventory.
    #[must_use]
    pub const fn inventory(&self) -> &PolicyInventory {
        &self.inventory
    }

    /// The correlators' drop counters, code integrity first.
    #[must_use]
    pub const fn correlator_stats(&self) -> [super::correlate::CorrelatorStats; 2] {
        [self.code_integrity.stats(), self.script_hosts.stats()]
    }

    /// Ingests one rendered record from a channel of `source`.
    pub fn push(&mut self, source: Source, xml: &[u8], ctx: &mut Context<'_>) {
        let groups = self.expire(ctx.now);
        self.emit_all(groups, ctx);
        let decoded = match decode(xml) {
            Ok(d) => d,
            Err(e) => {
                self.stats.undecoded = self.stats.undecoded.saturating_add(1);
                tracing::debug!(error = %e, "event-log record skipped");
                return;
            }
        };
        if !self.limiter.allow(ctx.now) {
            return;
        }
        self.inventory.observe(&decoded.record);
        let groups = match source {
            Source::CodeIntegrity => self.code_integrity.push(decoded.record, ctx.now),
            Source::RuleCollection => self.script_hosts.push(decoded.record, ctx.now),
            Source::PowerShell => vec![Group {
                record: decoded.record,
                signatures: Vec::new(),
                incomplete: false,
            }],
        };
        let kind = source_kind(source);
        self.emit_all(groups.into_iter().map(|g| (kind, g)).collect(), ctx);
    }

    /// Releases groups whose correlation wait has ended.
    pub fn tick(&mut self, ctx: &mut Context<'_>) {
        let groups = self.expire(ctx.now);
        self.emit_all(groups, ctx);
    }

    /// Releases every waiting group (on shutdown).
    pub fn flush(&mut self, ctx: &mut Context<'_>) {
        let mut groups: Vec<_> = self
            .code_integrity
            .flush()
            .into_iter()
            .map(|g| (SourceKind::OsCodeIntegrity, g))
            .collect();
        groups.extend(
            self.script_hosts
                .flush()
                .into_iter()
                .map(|g| (SourceKind::OsLegacyRuleCollection, g)),
        );
        self.emit_all(groups, ctx);
    }

    fn expire(&mut self, now: u64) -> Vec<(SourceKind, Group)> {
        let mut out: Vec<_> = self
            .code_integrity
            .expire(now)
            .into_iter()
            .map(|g| (SourceKind::OsCodeIntegrity, g))
            .collect();
        out.extend(
            self.script_hosts
                .expire(now)
                .into_iter()
                .map(|g| (SourceKind::OsLegacyRuleCollection, g)),
        );
        out
    }

    fn emit_all(&mut self, groups: Vec<(SourceKind, Group)>, ctx: &mut Context<'_>) {
        for (kind, group) in groups {
            self.emit(kind, &group, ctx);
        }
    }

    fn emit(&mut self, kind: SourceKind, group: &Group, ctx: &mut Context<'_>) {
        let envelope = ctx.envelopes.next();
        let mapped = match self
            .mappings
            .map(kind, &group.record, &group.signatures, &envelope)
        {
            Ok(m) => m,
            Err(MapError::Unmapped { .. }) => {
                self.stats.unmapped = self.stats.unmapped.saturating_add(1);
                return;
            }
            Err(e) => {
                self.stats.map_failed = self.stats.map_failed.saturating_add(1);
                tracing::debug!(error = %e, event_id = group.record.event_id, "event-log record not mapped");
                return;
            }
        };
        let mut event = mapped.event;
        if let Some(tree) = ctx.tree {
            enrich(&mut event, tree);
        }
        if group.incomplete || mapped.signatures_incomplete.is_some() {
            self.stats.incomplete = self.stats.incomplete.saturating_add(1);
        }
        if ctx.sink.offer(event) {
            self.stats.emitted = self.stats.emitted.saturating_add(1);
        } else {
            self.stats.sink_refused = self.stats.sink_refused.saturating_add(1);
        }
    }
}

const fn source_kind(source: Source) -> SourceKind {
    match source {
        Source::CodeIntegrity => SourceKind::OsCodeIntegrity,
        Source::RuleCollection => SourceKind::OsLegacyRuleCollection,
        Source::PowerShell => SourceKind::OsPowershell,
    }
}

/// Adds what the process tree knows about the event's process, keeping
/// every value the OS log supplied.
fn enrich(event: &mut Event, tree: &ProcessTree) {
    let Some(pid) = event.process.as_ref().and_then(|p| p.pid) else {
        return;
    };
    let at = UtcTime(event.ts.unix_micros());
    let Some(known) = tree.alive_at(pid, at) else {
        return;
    };
    let Some(from_tree) = process_fields(tree, known.key) else {
        return;
    };
    let own = event.process.get_or_insert_with(Process::default);
    own.process_key = own.process_key.take().or(from_tree.process_key);
    own.image_path = own.image_path.take().or(from_tree.image_path);
    own.image_path_normalised = own
        .image_path_normalised
        .take()
        .or(from_tree.image_path_normalised);
    own.cmdline = own.cmdline.take().or(from_tree.cmdline);
    own.integrity_level = own.integrity_level.or(from_tree.integrity_level);
    own.token_elevation_type = own.token_elevation_type.or(from_tree.token_elevation_type);
    own.owner_sid = own.owner_sid.take().or(from_tree.owner_sid);
    own.parent = own.parent.take().or(from_tree.parent);
    own.grandparent = own.grandparent.take().or(from_tree.grandparent);
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use palisade_core::platform::ProcessKey;
    use palisade_proto::events::{
        EventType, Host, HostId, Labels, Outcome, TenantId, Timestamp, Uuid7,
    };

    use super::super::decode::tests::ci_xml;
    use super::*;
    use crate::telemetry::tree::{CommandLine, ProcInfo};

    struct Envelopes(u64);
    impl EnvelopeSource for Envelopes {
        fn next(&mut self) -> Envelope {
            self.0 += 1;
            let id = |n: u64| {
                let mut b = [0_u8; 16];
                b[8..].copy_from_slice(&n.to_be_bytes());
                b[6] = 0x70;
                b[8] = 0x80;
                Uuid7::from_bytes(b).unwrap()
            };
            Envelope {
                event_id: id(self.0),
                tenant_id: TenantId(id(1_000_000)),
                host: Host {
                    id: HostId(id(2_000_000)),
                    ..serde_json::from_value(serde_json::json!({"id": id(2_000_000)})).unwrap()
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

    #[derive(Default)]
    struct Sink(Vec<Event>, bool);
    impl EventSink for Sink {
        fn offer(&mut self, event: Event) -> bool {
            if self.1 {
                return false;
            }
            self.0.push(event);
            true
        }
    }

    const ACT: &str = "{A244370E-44C9-4C06-B551-F6016E563076}";

    fn audit_3076(count: &str) -> String {
        ci_xml(
            3076,
            ACT,
            &[
                ("File Name", "\\Device\\HarddiskVolume3\\Temp\\a.exe"),
                (
                    "Process Name",
                    "\\Device\\HarddiskVolume3\\Windows\\explorer.exe",
                ),
                ("Requested Signing Level", "2"),
                ("Validated Signing Level", "1"),
                ("Status", "0xc0e90002"),
                (
                    "SHA256 Flat Hash",
                    "1111111111111111111111111111111111111111111111111111111111111111",
                ),
                ("PolicyName", "Audit policy"),
                ("SI Signing Scenario", "1"),
                ("TotalSignatureCount", count),
            ],
        )
    }

    fn sig_3089(index: &str) -> String {
        ci_xml(
            3089,
            ACT,
            &[
                ("TotalSignatureCount", "1"),
                ("Signature", index),
                ("PublisherName", "Test Publisher"),
                ("SignatureType", "1"),
                ("VerificationError", "7"),
            ],
        )
    }

    fn run(
        ingest: &mut Ingest,
        tree: Option<&ProcessTree>,
        steps: &[(Source, String, u64)],
    ) -> Sink {
        let mut sink = Sink::default();
        let mut env = Envelopes(0);
        for (source, xml, now) in steps {
            let mut ctx = Context {
                now: *now,
                tree,
                envelopes: &mut env,
                sink: &mut sink,
            };
            ingest.push(*source, xml.as_bytes(), &mut ctx);
        }
        sink
    }

    #[test]
    fn an_audit_block_and_its_signature_become_one_event() {
        let mut ingest = Ingest::new().unwrap();
        let sink = run(
            &mut ingest,
            None,
            &[
                (Source::CodeIntegrity, audit_3076("1"), 0),
                (Source::CodeIntegrity, sig_3089("0"), 10),
            ],
        );
        assert_eq!(sink.0.len(), 1, "{:?}", ingest.stats());
        let e = &sink.0[0];
        assert_eq!(e.event_type, EventType::ExecDecision);
        assert_eq!(e.outcome, Outcome::Audited);
        let file = e.file.as_ref().unwrap();
        assert_eq!(file.signers.len(), 1);
        assert!(file.hashes.sha256.is_some());
        assert_eq!(ingest.stats().emitted, 1);
        assert_eq!(ingest.stats().incomplete, 0);
    }

    #[test]
    fn a_late_signature_is_waited_for_then_released_incomplete() {
        let mut ingest = Ingest::with(MappingSet::builtin().unwrap(), 100, 1000);
        let mut sink = run(
            &mut ingest,
            None,
            &[(Source::CodeIntegrity, audit_3076("2"), 0)],
        );
        assert!(sink.0.is_empty());
        let mut env = Envelopes(0);
        ingest.tick(&mut Context {
            now: 1000,
            tree: None,
            envelopes: &mut env,
            sink: &mut sink,
        });
        assert_eq!(sink.0.len(), 1);
        assert_eq!(ingest.stats().incomplete, 1);
        // Flush releases anything still waiting.
        run(
            &mut ingest,
            None,
            &[(Source::CodeIntegrity, audit_3076("1"), 2000)],
        );
        ingest.flush(&mut Context {
            now: 2001,
            tree: None,
            envelopes: &mut env,
            sink: &mut sink,
        });
        assert_eq!(sink.0.len(), 2);
    }

    #[test]
    fn the_process_tree_adds_parent_and_command_line() {
        let mut tree = ProcessTree::new(10, Duration::from_secs(600));
        let at = Timestamp::parse_utc("2026-11-24T03:15:22.123456Z")
            .unwrap()
            .unix_micros();
        let parent = ProcInfo::new(
            ProcessKey {
                pid: 3,
                created: UtcTime(at - 100),
            },
            0,
            "C:\\Windows\\explorer.exe".into(),
        );
        tree.insert(parent);
        let mut p = ProcInfo::new(
            ProcessKey {
                pid: 4,
                created: UtcTime(at - 10),
            },
            3,
            "C:\\Windows\\System32\\a.exe".into(),
        );
        p.parent = Some(ProcessKey {
            pid: 3,
            created: UtcTime(at - 100),
        });
        p.command_line = CommandLine::Captured {
            text: "a.exe /x".into(),
            truncated: false,
        };
        tree.insert(p);
        let mut ingest = Ingest::new().unwrap();
        let sink = run(
            &mut ingest,
            Some(&tree),
            &[
                (Source::CodeIntegrity, audit_3076("1"), 0),
                (Source::CodeIntegrity, sig_3089("0"), 1),
            ],
        );
        let proc = sink.0[0].process.as_ref().unwrap();
        assert_eq!(proc.pid, Some(4));
        assert_eq!(proc.cmdline.as_ref().unwrap().as_str(), "a.exe /x");
        assert_eq!(proc.parent.as_ref().unwrap().pid, Some(3));
        // The OS log's own image path is kept.
        assert!(
            proc.image_path
                .as_ref()
                .unwrap()
                .as_str()
                .contains("explorer.exe")
        );
        // A PID the tree does not know adds nothing.
        let empty = ProcessTree::new(1, Duration::from_secs(1));
        let mut ingest = Ingest::new().unwrap();
        let sink = run(
            &mut ingest,
            Some(&empty),
            &[
                (Source::CodeIntegrity, audit_3076("1"), 0),
                (Source::CodeIntegrity, sig_3089("0"), 1),
            ],
        );
        assert!(sink.0[0].process.as_ref().unwrap().cmdline.is_none());
    }

    #[test]
    fn policy_activations_fill_the_inventory() {
        let mut ingest = Ingest::new().unwrap();
        let x = ci_xml(
            3099,
            ACT,
            &[
                ("PolicyNameBuffer", "Base"),
                ("PolicyIdBuffer", "Base"),
                ("PolicyGUID", ACT),
                ("Options", "65540"),
                ("Status", "0x0"),
            ],
        );
        let sink = run(&mut ingest, None, &[(Source::CodeIntegrity, x, 0)]);
        assert_eq!(sink.0.len(), 1);
        assert_eq!(sink.0[0].event_type, EventType::PolicyActivated);
        let p = ingest.inventory().policies().next().unwrap();
        assert_eq!(p.option_names(), ["UMCI", "Audit"]);
    }

    #[test]
    fn every_failure_is_counted() {
        let mut ingest = Ingest::with(MappingSet::builtin().unwrap(), 2, DEFAULT_WAIT);
        let unmapped = ci_xml(3999, ACT, &[]);
        let ps = format!(
            "<Event xmlns=\"{}\"><System><EventID>16387</EventID>\
             <TimeCreated SystemTime=\"2026-11-24T03:15:22Z\"/></System></Event>",
            super::super::os_ids::EVENT_NS
        );
        let sink = run(
            &mut ingest,
            None,
            &[
                (Source::CodeIntegrity, "<bad".into(), 0),
                (Source::CodeIntegrity, unmapped, 0),
                (Source::PowerShell, ps.clone(), 0),
                (Source::PowerShell, ps, 0),
            ],
        );
        let s = ingest.stats();
        assert_eq!(s.undecoded, 1);
        assert_eq!(s.unmapped, 1);
        // The rate (2 a second) admits the unmapped record and one script
        // audit; the second script audit is over it.
        assert_eq!(s.rate_limited, 1);
        assert_eq!(s.emitted + s.map_failed, 1);
        assert_eq!(sink.0.len(), usize::try_from(s.emitted).unwrap());
        assert_eq!(ingest.correlator_stats()[0], Default::default());
        assert!(format!("{ingest:?}").contains("Ingest"));

        // A refusing sink is counted.
        let mut ingest = Ingest::new().unwrap();
        let mut sink = Sink(Vec::new(), true);
        let mut env = Envelopes(0);
        ingest.push(
            Source::CodeIntegrity,
            audit_3076("0").as_bytes(),
            &mut Context {
                now: 0,
                tree: None,
                envelopes: &mut env,
                sink: &mut sink,
            },
        );
        assert_eq!(ingest.stats().sink_refused, 1);
    }

    #[test]
    fn a_record_that_cannot_map_is_counted() {
        let mut ingest = Ingest::new().unwrap();
        // A 3077 kernel-mode block with no file name has nothing to fill
        // its required `file` field set from.
        let x = ci_xml(3077, ACT, &[("SI Signing Scenario", "0")]);
        let sink = run(&mut ingest, None, &[(Source::CodeIntegrity, x, 0)]);
        assert!(sink.0.is_empty());
        assert_eq!(ingest.stats().map_failed, 1);
    }

    #[test]
    fn script_host_records_go_through_the_rule_collection_mapping() {
        let mut ingest = Ingest::new().unwrap();
        let x = format!(
            "<Event xmlns=\"{}\"><System><EventID>8004</EventID>\
             <TimeCreated SystemTime=\"2026-11-24T03:15:22Z\"/></System>\
             <UserData><RuleAndFileData><PolicyNameBuffer>EXE</PolicyNameBuffer>\
             <FullFilePathBuffer>C:\\t\\a.exe</FullFilePathBuffer>\
             <TargetUser>S-1-5-21-1-2-3-1001</TargetUser>\
             <TargetProcessId>77</TargetProcessId></RuleAndFileData></UserData></Event>",
            super::super::os_ids::EVENT_NS
        );
        let sink = run(&mut ingest, None, &[(Source::RuleCollection, x, 0)]);
        assert_eq!(sink.0.len(), 1, "{:?}", ingest.stats());
        assert_eq!(sink.0[0].outcome, Outcome::Blocked);
    }
}
