//! Classification, allowed-execution summaries and de-duplication (#63,
//! #197).
//!
//! [`classify`] puts an event in a spool [`Class`] from its type and
//! outcome. [`Aggregator`] then decides, per event, whether it is sent in
//! full, folded into a summary, or folded into a repeat count. It is a pure
//! state machine: time comes in as an argument, so it is tested without a
//! clock.
//!
//! - **Summary** ([`AllowedMode::Summary`], the default): an allowed
//!   decision of a summarisable type is folded into a summary per
//!   (user, process image, parent image, object, outcome, rule, policy
//!   version) over a window ([`AggregateSettings::summary_window`],
//!   default 1 h, 5 min to 24 h). The first occurrence in a window is
//!   kept as the summary's representative event. Up to 3 distinct command
//!   lines are kept. At the window's end the summary is emitted with its
//!   exact count; every [`AggregateSettings::partial_every`] (default 5
//!   min) a partial summary carries the counts since the last one, so a
//!   crash loses at most that much (#63).
//! - **First seen**: an allowed occurrence of a tuple not seen in this
//!   window is sent in full; the rest are counted into the summary, which
//!   then carries only the repeats (#197 `first_seen`).
//! - **Complete** sends every allowed event in full; **off** sends none
//!   and counts them, so the console can warn that ISM-1660 evidence is
//!   missing.
//! - **De-duplication** of blocked and audited decisions: an identical
//!   tuple within [`AggregateSettings::dedup_window`] (default 10 min) is
//!   collapsed into the first full event plus a repeat-count event at the
//!   window's end (#63). Security and information events (process
//!   creation, policy state) are never de-duplicated: each is evidence on
//!   its own, and process creation must keep every command line
//!   (ISM-1889).
//!
//! Counts are exact: every occurrence is in exactly one full event or one
//! aggregate (a property test checks this). The table is bounded
//! ([`AggregateSettings::max_keys`]); when it is full, a new tuple is sent
//! in full instead of being folded, so the cap never loses an event.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::num::NonZeroU64;
use std::time::Duration;

use palisade_proto::events::{
    Aggregate, AggregateKind, BoundedVec, Category, Event, EventType, LongText, Outcome, Timestamp,
};

use super::segment::Class;

/// The spool class of `event`.
#[must_use]
pub fn classify(event: &Event) -> Class {
    let ty = event.event_type;
    if is_security(ty) {
        return Class::Security;
    }
    match event.outcome {
        Outcome::Blocked => Class::Blocked,
        Outcome::Audited => Class::Audit,
        Outcome::Allowed | Outcome::Elevated if ty.summarisable() => {
            if event
                .aggregate
                .as_ref()
                .is_some_and(|a| a.kind == AggregateKind::Summary)
            {
                Class::Summary
            } else {
                Class::Allowed
            }
        }
        _ if ty == EventType::ExecOriginCheck => Class::Diagnostic,
        _ => Class::Info,
    }
}

/// Tamper, agent-health and other events the spool keeps longest, uploads
/// first and never de-duplicates.
fn is_security(ty: EventType) -> bool {
    matches!(
        ty,
        EventType::AgentTamper
            | EventType::AgentDropped
            | EventType::AgentThrottled
            | EventType::AgentClockUnsynced
            | EventType::AgentHealth
            | EventType::AgentStarted
            | EventType::AgentStopped
            | EventType::TamperPolicyRollbackSuspected
            | EventType::PolicyEmergencyLoaded
            | EventType::PolicyLkgLoaded
            | EventType::PolicySignatureInvalid
            | EventType::PolicyRollbackRejected
            | EventType::DetectionLogCleared
            | EventType::DetectionAuditPolicyChanged
    ) || ty.category() == Category::AdminAudit
}

/// How allowed decisions of summarisable types are reported
/// (`allowed_events.mode`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AllowedMode {
    /// Every allowed decision in full.
    Complete,
    /// The first occurrence of each tuple per window in full, the rest
    /// counted.
    FirstSeen,
    /// Rolled up per tuple and window. The default.
    #[default]
    Summary,
    /// Not reported, only counted. Only for configured exceptions; the
    /// console warns that ISM-1660 evidence is missing.
    Off,
}

/// The aggregator's settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregateSettings {
    /// The allowed-events mode.
    pub allowed: AllowedMode,
    /// The summary window: 5 minutes to 24 hours, default 1 hour.
    pub summary_window: Duration,
    /// How often partial summaries are written: default 5 minutes.
    pub partial_every: Duration,
    /// The de-duplication window for non-summarisable events: default 10
    /// minutes. Zero turns de-duplication off.
    pub dedup_window: Duration,
    /// The most tuples held at once.
    pub max_keys: usize,
}

impl Default for AggregateSettings {
    fn default() -> Self {
        Self {
            allowed: AllowedMode::Summary,
            summary_window: Duration::from_secs(60 * 60),
            partial_every: Duration::from_secs(5 * 60),
            dedup_window: Duration::from_secs(10 * 60),
            max_keys: 100_000,
        }
    }
}

impl AggregateSettings {
    /// The shortest summary window.
    pub const MIN_WINDOW: Duration = Duration::from_secs(5 * 60);
    /// The longest summary window.
    pub const MAX_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

    /// The summary window, clamped to its range.
    #[must_use]
    pub fn window(&self) -> Duration {
        self.summary_window
            .clamp(Self::MIN_WINDOW, Self::MAX_WINDOW)
    }
}

/// What to do with one event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Send it in full.
    Forward(Box<Event>),
    /// It was counted into an aggregate; nothing to send now.
    Folded,
    /// It was counted, but the mode reports nothing (allowed mode `off`).
    Suppressed,
}

/// Counters for health and metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AggregateStats {
    /// Events seen.
    pub seen: u64,
    /// Events sent in full.
    pub forwarded: u64,
    /// Events counted into summaries or repeat counts.
    pub folded: u64,
    /// Allowed events not reported (`off`).
    pub suppressed: u64,
    /// Aggregate events emitted.
    pub aggregates: u64,
    /// New tuples sent in full because the table was full.
    pub table_full: u64,
}

/// The tuple an occurrence is grouped by. A 64-bit hash of the fields;
/// a collision folds two tuples together, which only merges counts (and is
/// vanishingly rare), never loses one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Key {
    summary: bool,
    hash: u64,
}

fn key_of(event: &Event, summary: bool) -> Key {
    fn text<const N: usize>(t: Option<&palisade_proto::events::Text<N>>) -> Option<&str> {
        t.map(palisade_proto::events::Text::as_str)
    }
    let mut h = DefaultHasher::new();
    event.event_type.as_str().hash(&mut h);
    event.outcome.hash(&mut h);
    event.mode.hash(&mut h);
    if let Some(u) = &event.user {
        u.sid.as_ref().map(|s| s.as_str()).hash(&mut h);
        text(u.name.as_ref()).hash(&mut h);
    }
    if let Some(p) = &event.process {
        text(p.image_path.as_ref()).hash(&mut h);
        p.hashes.sha256.hash(&mut h);
        if let Some(parent) = &p.parent {
            text(parent.image_path.as_ref()).hash(&mut h);
            parent.hashes.sha256.hash(&mut h);
        }
    }
    if let Some(f) = &event.file {
        // The hash when there is one, the path otherwise (#63).
        match f.hashes.sha256 {
            Some(d) => d.hash(&mut h),
            None => text(f.path.as_ref()).hash(&mut h),
        }
        text(f.package_name.as_ref()).hash(&mut h);
    }
    if let Some(s) = &event.script {
        text(s.path.as_ref()).hash(&mut h);
        s.content_sha256.hash(&mut h);
    }
    if let Some(p) = &event.policy {
        p.rule_id.hash(&mut h);
        p.version.hash(&mut h);
    }
    // Events with none of the above (agent, network and so on) also group
    // by their canonical form less the per-occurrence fields, so unrelated
    // events are never merged.
    if event.file.is_none() && event.script.is_none() && event.process.is_none() {
        let mut bare = event.clone();
        bare.event_id = BARE_ID;
        bare.ts = Timestamp::MIN;
        bare.ts_agent_monotonic = None;
        bare.seq = 0;
        bare.prev_hash = None;
        bare.to_canonical_json().unwrap_or_default().hash(&mut h);
    }
    Key {
        summary,
        hash: h.finish(),
    }
}

/// The event ID put on a copy that is hashed for grouping: every
/// occurrence has its own ID, so it must not count.
const BARE_ID: palisade_proto::events::Uuid7 = super::fixed_uuid(0);

/// One tuple's open aggregate.
#[derive(Clone, Debug)]
struct Open {
    /// The representative occurrence: the first in the window.
    sample: Box<Event>,
    /// When the window closes, in microseconds since the epoch.
    closes: i64,
    /// When the next partial summary is due.
    partial_due: i64,
    /// Occurrences counted since the last aggregate event.
    count: u64,
    first: Timestamp,
    last: Timestamp,
    samples: Vec<LongText>,
}

/// The aggregator (see the module docs).
#[derive(Debug)]
pub struct Aggregator {
    settings: AggregateSettings,
    open: HashMap<Key, Open>,
    /// Aggregates closed by [`Aggregator::offer`], for the next tick.
    pending: Vec<Event>,
    stats: AggregateStats,
}

fn micros(d: Duration) -> i64 {
    i64::try_from(d.as_micros()).unwrap_or(i64::MAX)
}

impl Aggregator {
    /// An aggregator with `settings`.
    #[must_use]
    pub fn new(settings: AggregateSettings) -> Self {
        Self {
            settings,
            open: HashMap::new(),
            pending: Vec::new(),
            stats: AggregateStats::default(),
        }
    }

    /// Changes the settings (a new policy). Open aggregates are flushed
    /// first, so no count is carried across a change of mode or window.
    pub fn reconfigure(&mut self, settings: AggregateSettings) -> Vec<Event> {
        let out = self.flush_all();
        self.settings = settings;
        out
    }

    /// The counters.
    #[must_use]
    pub const fn stats(&self) -> AggregateStats {
        self.stats
    }

    /// Open tuples.
    #[must_use]
    pub fn open_tuples(&self) -> usize {
        self.open.len()
    }

    /// Decides what to do with `event`. Its `ts` is the time used for the
    /// windows. With `force_summary` (the throttle is above its high
    /// watermark), allowed events are summarised whatever the mode.
    pub fn offer(&mut self, event: Event, force_summary: bool) -> Disposition {
        self.stats.seen = self.stats.seen.saturating_add(1);
        let now = event.ts.unix_micros();
        let class = classify(&event);
        let summarisable = matches!(class, Class::Allowed) && event.outcome == Outcome::Allowed;
        let mode = if force_summary && self.settings.allowed != AllowedMode::Off {
            AllowedMode::Summary
        } else {
            self.settings.allowed
        };
        let (fold, window, first_in_full) = if summarisable {
            match mode {
                AllowedMode::Complete => return self.forward(event),
                AllowedMode::Off => {
                    self.stats.suppressed = self.stats.suppressed.saturating_add(1);
                    return Disposition::Suppressed;
                }
                AllowedMode::Summary => (true, self.settings.window(), false),
                AllowedMode::FirstSeen => (true, self.settings.window(), true),
            }
        } else if !matches!(class, Class::Blocked | Class::Audit)
            || event.aggregate.is_some()
            || self.settings.dedup_window.is_zero()
        {
            (false, Duration::ZERO, true)
        } else {
            (true, self.settings.dedup_window, true)
        };
        if !fold {
            return self.forward(event);
        }
        let key = key_of(&event, summarisable);
        let ts = event.ts;
        let cmdline = event.process.as_ref().and_then(|p| p.cmdline.clone());
        // A window that has passed but not been ticked yet is closed now,
        // so its count is never mixed with the next window's.
        if self.open.get(&key).is_some_and(|o| now >= o.closes)
            && let Some(mut stale) = self.open.remove(&key)
        {
            let window = if key.summary {
                micros(self.settings.window())
            } else {
                0
            };
            if let Some(e) = emit(&mut stale, false, window) {
                self.stats.aggregates = self.stats.aggregates.saturating_add(1);
                self.pending.push(e);
            }
        }
        if let Some(open) = self.open.get_mut(&key) {
            open.count = open.count.saturating_add(1);
            open.last = open.last.max(ts);
            open.first = open.first.min(ts);
            if let Some(c) = cmdline
                && open.samples.len() < 3
                && !open.samples.contains(&c)
            {
                open.samples.push(c);
            }
            self.stats.folded = self.stats.folded.saturating_add(1);
            return Disposition::Folded;
        }
        if self.open.len() >= self.settings.max_keys {
            self.stats.table_full = self.stats.table_full.saturating_add(1);
            return self.forward(event);
        }
        let partial = if summarisable {
            micros(self.settings.partial_every.max(Duration::from_secs(1)))
        } else {
            i64::MAX
        };
        let mut open = Open {
            sample: Box::new(event.clone()),
            closes: now.saturating_add(micros(window)),
            partial_due: now.saturating_add(partial),
            count: 0,
            first: ts,
            last: ts,
            samples: cmdline.into_iter().collect(),
        };
        if first_in_full {
            // The first occurrence goes in full; the aggregate counts only
            // the repeats after it.
            open.samples.clear();
            self.open.insert(key, open);
            return self.forward(event);
        }
        open.count = 1;
        self.open.insert(key, open);
        self.stats.folded = self.stats.folded.saturating_add(1);
        Disposition::Folded
    }

    fn forward(&mut self, event: Event) -> Disposition {
        self.stats.forwarded = self.stats.forwarded.saturating_add(1);
        Disposition::Forward(Box::new(event))
    }

    /// Emits what is due at `now`: closed windows, and partial summaries.
    pub fn tick(&mut self, now: i64) -> Vec<Event> {
        let mut out = std::mem::take(&mut self.pending);
        let carried = out.len();
        let partial = micros(self.settings.partial_every.max(Duration::from_secs(1)));
        let window = micros(self.settings.window());
        let mut closed = Vec::new();
        for (key, open) in &mut self.open {
            if now >= open.closes {
                closed.push(*key);
            } else if key.summary && now >= open.partial_due {
                open.partial_due = now.saturating_add(partial);
                if let Some(e) = emit(open, true, window) {
                    out.push(e);
                }
            }
        }
        closed.sort_by_key(|k| self.open.get(k).map(|o| o.first));
        for key in closed {
            if let Some(mut open) = self.open.remove(&key)
                && let Some(e) = emit(&mut open, false, if key.summary { window } else { 0 })
            {
                out.push(e);
            }
        }
        self.stats.aggregates = self
            .stats
            .aggregates
            .saturating_add(u64::try_from(out.len() - carried).unwrap_or(u64::MAX));
        out
    }

    /// Emits every open aggregate, as on shutdown or a policy change.
    pub fn flush_all(&mut self) -> Vec<Event> {
        let window = micros(self.settings.window());
        let mut open: Vec<(Key, Open)> = self.open.drain().collect();
        open.sort_by_key(|(_, o)| o.first);
        let mut out = std::mem::take(&mut self.pending);
        let carried = out.len();
        out.extend(
            open.into_iter().filter_map(|(key, mut o)| {
                emit(&mut o, false, if key.summary { window } else { 0 })
            }),
        );
        self.stats.aggregates = self
            .stats
            .aggregates
            .saturating_add(u64::try_from(out.len() - carried).unwrap_or(u64::MAX));
        out
    }
}

/// The aggregate event for `open`'s counts since the last one, and resets
/// them. `None` when there is nothing to report.
fn emit(open: &mut Open, partial: bool, window_micros: i64) -> Option<Event> {
    let count = NonZeroU64::new(open.count)?;
    let mut event = (*open.sample).clone();
    let summary = window_micros > 0;
    event.aggregate = Some(Aggregate {
        kind: if summary {
            AggregateKind::Summary
        } else {
            AggregateKind::Repeat
        },
        count,
        first_seen: open.first,
        last_seen: open.last,
        window_secs: summary.then(|| u32::try_from(window_micros / 1_000_000).unwrap_or(u32::MAX)),
        partial,
        cmdline_samples: BoundedVec::new(std::mem::take(&mut open.samples)).unwrap_or_default(),
    });
    // A repeat count of a non-summarisable event keeps its outcome; a
    // summary is only ever of allowed decisions.
    open.count = 0;
    open.first = open.last;
    Some(event)
}

#[cfg(test)]
mod tests;
