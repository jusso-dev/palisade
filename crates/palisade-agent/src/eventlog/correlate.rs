//! Grouping decision records with their per-signature records (#58).
//!
//! The OS code integrity log writes a block or audit decision (3076, 3077)
//! followed by one signature record (3089) per signature, all with the
//! same correlation activity ID. The decision says how many signatures
//! follow (`TotalSignatureCount`). Script hosts do the same in the
//! rule-collection log (8028, 8029, then 8038 per signature). The
//! [`Correlator`] holds each decision until all its signatures have
//! arrived, or until [`DEFAULT_WAIT`] (2 s) has passed, and then releases
//! the group for mapping. Every other record passes straight through.
//!
//! Signature records that arrive before their decision are held too, for
//! the same window, so the order in which the subscription delivers them
//! does not matter.
//!
//! Limits, all counted, never silent: at most [`MAX_PENDING`] groups wait
//! at once (the oldest is released early, incomplete, when it is full); a
//! group holds at most 64 signatures, the schema's limit; and orphan
//! signature records that never meet their decision are dropped when their
//! window ends.
//!
//! Before correlation, a token bucket ([`RateLimiter`]) bounds the rate
//! (2,000 records a second by default), so an audit storm cannot exhaust
//! memory. Records over the rate are dropped and counted.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, VecDeque};

use palisade_proto::events::{Guid, MAX_SIGNERS};
use palisade_proto::mapping::Record;

/// How long a decision waits for its signature records, in microseconds.
pub const DEFAULT_WAIT: u64 = 2_000_000;
/// The most groups waiting at once.
pub const MAX_PENDING: usize = 4096;
/// The default rate limit, in records a second.
pub const DEFAULT_RATE: u32 = 2000;

/// Which records belong together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pairing {
    /// The decision event IDs.
    pub decisions: &'static [u32],
    /// The signature record's event ID.
    pub signature: u32,
    /// The decision's field with the signature count.
    pub count_field: &'static str,
}

/// The code integrity pairing: 3076 and 3077 with 3089.
pub const CODE_INTEGRITY: Pairing = Pairing {
    decisions: &[3076, 3077],
    signature: 3089,
    count_field: "TotalSignatureCount",
};

/// The script host pairing in the rule-collection log: 8028 and 8029 with
/// 8038.
pub const SCRIPT_HOSTS: Pairing = Pairing {
    decisions: &[8028, 8029],
    signature: 8038,
    count_field: "TotalSignatureCount",
};

/// A decision with its signature records, ready for mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    /// The decision, or any other record that needs no correlation.
    pub record: Record,
    /// Its signature records, in arrival order.
    pub signatures: Vec<Record>,
    /// Whether the group was released before every announced signature
    /// arrived (time out, or the pending table was full).
    pub incomplete: bool,
}

/// What the correlator has dropped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CorrelatorStats {
    /// Signature records whose decision never arrived.
    pub orphan_signatures: u64,
    /// Signature records past a group's limit.
    pub excess_signatures: u64,
    /// Groups released early because the table was full.
    pub evicted: u64,
    /// Groups released incomplete after the wait.
    pub timed_out: u64,
}

impl Group {
    /// A record with no signatures, complete.
    fn alone(record: Record) -> Self {
        Self {
            record,
            signatures: Vec::new(),
            incomplete: false,
        }
    }
}

struct Pending {
    decision: Option<Record>,
    signatures: Vec<Record>,
    deadline: u64,
}

/// The correlator for one pairing.
pub struct Correlator {
    pairing: Pairing,
    wait: u64,
    pending: BTreeMap<Guid, Pending>,
    order: VecDeque<(u64, Guid)>,
    stats: CorrelatorStats,
}

impl std::fmt::Debug for Correlator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Correlator")
            .field("pending", &self.pending.len())
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl Correlator {
    /// A correlator for `pairing` that waits `wait` microseconds.
    #[must_use]
    pub fn new(pairing: Pairing, wait: u64) -> Self {
        Self {
            pairing,
            wait,
            pending: BTreeMap::new(),
            order: VecDeque::new(),
            stats: CorrelatorStats::default(),
        }
    }

    /// What has been dropped so far.
    #[must_use]
    pub const fn stats(&self) -> CorrelatorStats {
        self.stats
    }

    /// How many groups are waiting.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Takes one record, at monotonic time `now` (microseconds), and
    /// returns the groups it releases.
    pub fn push(&mut self, record: Record, now: u64) -> Vec<Group> {
        let mut out = self.expire(now);
        let is_decision = self.pairing.decisions.contains(&record.event_id);
        let is_signature = record.event_id == self.pairing.signature;
        if !is_decision && !is_signature {
            out.push(Group::alone(record));
            return out;
        }
        let Some(activity) = record.activity_id else {
            if is_signature {
                // A signature record with no activity ID can never be
                // matched.
                self.stats.orphan_signatures += 1;
            } else {
                // Nor can a decision's signatures: release it as it is.
                let incomplete = announced(&self.pairing, &record) > 0;
                out.push(Group {
                    incomplete,
                    ..Group::alone(record)
                });
            }
            return out;
        };
        if is_decision && announced(&self.pairing, &record) == 0 {
            // No signatures announced: nothing to wait for.
            out.push(Group::alone(record));
            return out;
        }
        if !self.pending.contains_key(&activity) {
            if self.pending.len() >= MAX_PENDING
                && let Some(g) = self.evict_oldest()
            {
                out.push(g);
            }
            self.pending.insert(
                activity,
                Pending {
                    decision: None,
                    signatures: Vec::new(),
                    deadline: now.saturating_add(self.wait),
                },
            );
            self.order
                .push_back((now.saturating_add(self.wait), activity));
        }
        let Some(p) = self.pending.get_mut(&activity) else {
            return out;
        };
        if is_decision {
            if let Some(previous) = p.decision.replace(record) {
                // A second decision with the same activity ID: release the
                // first as it is, so neither is lost.
                out.push(Group {
                    record: previous,
                    signatures: Vec::new(),
                    incomplete: true,
                });
            }
        } else if p.signatures.len() < MAX_SIGNERS {
            p.signatures.push(record);
        } else {
            self.stats.excess_signatures += 1;
        }
        if let Some(count) = p.decision.as_ref().map(|d| announced(&self.pairing, d))
            && p.signatures.len() >= count
            && let Some(done) = self.pending.remove(&activity)
            && let Some(record) = done.decision
        {
            out.push(Group {
                record,
                signatures: done.signatures,
                incomplete: false,
            });
        }
        out
    }

    /// Releases the groups whose wait has ended by `now`.
    pub fn expire(&mut self, now: u64) -> Vec<Group> {
        let mut out = Vec::new();
        while let Some(&(deadline, activity)) = self.order.front() {
            if deadline > now {
                break;
            }
            self.order.pop_front();
            let still_pending = self
                .pending
                .get(&activity)
                .is_some_and(|p| p.deadline == deadline);
            if !still_pending {
                continue;
            }
            if let Some(g) = self.release(activity) {
                self.stats.timed_out += 1;
                out.push(g);
            }
        }
        out
    }

    /// Releases every waiting group (on shutdown).
    pub fn flush(&mut self) -> Vec<Group> {
        let keys: Vec<Guid> = self.pending.keys().copied().collect();
        self.order.clear();
        keys.into_iter().filter_map(|k| self.release(k)).collect()
    }

    fn evict_oldest(&mut self) -> Option<Group> {
        while let Some((deadline, activity)) = self.order.pop_front() {
            if self
                .pending
                .get(&activity)
                .is_some_and(|p| p.deadline == deadline)
            {
                self.stats.evicted += 1;
                return self.release(activity);
            }
        }
        None
    }

    fn release(&mut self, activity: Guid) -> Option<Group> {
        let p = self.pending.remove(&activity)?;
        match p.decision {
            Some(record) => Some(Group {
                record,
                signatures: p.signatures,
                incomplete: true,
            }),
            None => {
                self.stats.orphan_signatures = self
                    .stats
                    .orphan_signatures
                    .saturating_add(u64::try_from(p.signatures.len()).unwrap_or(u64::MAX));
                None
            }
        }
    }
}

/// The signature count `decision` announces, capped at the schema's
/// limit. A missing or unreadable count is 0: nothing can be waited for.
fn announced(pairing: &Pairing, decision: &Record) -> usize {
    decision
        .fields
        .get(pairing.count_field)
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0)
        .min(MAX_SIGNERS)
}

/// A token bucket: at most `rate` records a second, with bursts of up to
/// one second's worth.
#[derive(Clone, Debug)]
pub struct RateLimiter {
    rate: u64,
    tokens: u64,
    last: u64,
    dropped: u64,
}

impl RateLimiter {
    /// A full bucket for `rate` records a second (at least 1).
    #[must_use]
    pub fn new(rate: u32) -> Self {
        let rate = u64::from(rate.max(1));
        Self {
            rate,
            tokens: rate * 1_000_000,
            last: 0,
            dropped: 0,
        }
    }

    /// Whether a record at monotonic time `now` (microseconds) may pass.
    /// A refused record is counted in [`RateLimiter::dropped`].
    pub fn allow(&mut self, now: u64) -> bool {
        let cap = self.rate * 1_000_000;
        let elapsed = now.saturating_sub(self.last);
        self.last = self.last.max(now);
        self.tokens = self
            .tokens
            .saturating_add(elapsed.saturating_mul(self.rate))
            .min(cap);
        // One record costs a million token units (one second / rate).
        if self.tokens >= 1_000_000 {
            self.tokens -= 1_000_000;
            true
        } else {
            self.dropped += 1;
            false
        }
    }

    /// How many records were refused.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use palisade_proto::events::Timestamp;

    use super::*;

    fn guid(n: u8) -> Guid {
        format!("a244370e-44c9-4c06-b551-f6016e5630{n:02x}")
            .parse()
            .unwrap()
    }

    fn rec(id: u32, activity: Option<u8>, fields: &[(&str, &str)]) -> Record {
        Record {
            event_id: id,
            time_created: Timestamp::from_unix_micros(0).unwrap(),
            record_id: None,
            channel: None,
            activity_id: activity.map(guid),
            fields: fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    fn decision(activity: u8, count: &str) -> Record {
        rec(3076, Some(activity), &[("TotalSignatureCount", count)])
    }

    fn sig(activity: u8, index: &str) -> Record {
        rec(3089, Some(activity), &[("Signature", index)])
    }

    fn c() -> Correlator {
        Correlator::new(CODE_INTEGRITY, DEFAULT_WAIT)
    }

    #[test]
    fn a_decision_waits_for_every_signature() {
        let mut c = c();
        assert!(c.push(decision(1, "2"), 0).is_empty());
        assert!(c.push(sig(1, "1"), 10).is_empty());
        let out = c.push(sig(1, "2"), 20);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].signatures.len(), 2);
        assert!(!out[0].incomplete);
        assert_eq!(c.pending(), 0);
        assert!(format!("{c:?}").contains("Correlator"));
    }

    #[test]
    fn signatures_may_come_first() {
        let mut c = c();
        assert!(c.push(sig(1, "1"), 0).is_empty());
        let out = c.push(decision(1, "1"), 5);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].signatures.len(), 1);
    }

    #[test]
    fn a_missing_signature_times_out_incomplete() {
        let mut c = c();
        c.push(decision(1, "3"), 0);
        c.push(sig(1, "1"), 1);
        assert!(c.expire(DEFAULT_WAIT - 1).is_empty());
        let out = c.expire(DEFAULT_WAIT);
        assert_eq!(out.len(), 1);
        assert!(out[0].incomplete);
        assert_eq!(c.stats().timed_out, 1);
        // Expiry also runs on push.
        c.push(decision(2, "1"), 10 * DEFAULT_WAIT);
        let out = c.push(rec(3001, None, &[]), 20 * DEFAULT_WAIT);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn orphans_and_unpaired_records_are_handled() {
        let mut c = c();
        // Other records pass through at once.
        let out = c.push(rec(3099, None, &[]), 0);
        assert_eq!(out.len(), 1);
        assert!(!out[0].incomplete);
        // A decision without an activity ID cannot be paired.
        let out = c.push(rec(3077, None, &[("TotalSignatureCount", "1")]), 0);
        assert_eq!(out.len(), 1);
        // A decision announcing no signatures passes at once.
        for count in ["0", "x"] {
            let out = c.push(decision(5, count), 0);
            assert_eq!(out.len(), 1);
            assert!(!out[0].incomplete);
        }
        // A signature with no activity ID, or whose decision never comes.
        assert!(c.push(rec(3089, None, &[]), 0).is_empty());
        c.push(sig(7, "1"), 0);
        c.push(sig(7, "2"), 0);
        assert!(c.expire(DEFAULT_WAIT).is_empty());
        assert_eq!(c.stats().orphan_signatures, 3);
    }

    #[test]
    fn a_repeated_decision_releases_the_first() {
        let mut c = c();
        c.push(decision(1, "1"), 0);
        let out = c.push(decision(1, "1"), 1);
        assert_eq!(out.len(), 1);
        assert!(out[0].incomplete);
        let out = c.push(sig(1, "1"), 2);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn limits_are_counted() {
        let mut c = c();
        c.push(decision(1, "999"), 0);
        for i in 0..=MAX_SIGNERS {
            let out = c.push(sig(1, &i.to_string()), 1);
            if i + 1 == MAX_SIGNERS {
                assert_eq!(out.len(), 1, "the count is capped at the schema limit");
            }
        }
        // The 65th signature starts an orphan group of its own.
        assert_eq!(c.pending(), 1);
        let mut c = Correlator::new(CODE_INTEGRITY, DEFAULT_WAIT);
        for i in 0..MAX_PENDING {
            let n = u8::try_from(i % 200).unwrap();
            let mut d = decision(n, "1");
            d.activity_id = Some(format!("a244370e-44c9-4c06-b551-{i:012x}").parse().unwrap());
            c.push(d, 0);
        }
        assert_eq!(c.pending(), MAX_PENDING);
        let out = c.push(decision(255, "1"), 1);
        assert_eq!(out.len(), 1);
        assert!(out[0].incomplete);
        assert_eq!(c.stats().evicted, 1);
        assert_eq!(c.flush().len(), MAX_PENDING);
        assert_eq!(c.pending(), 0);
    }

    #[test]
    fn excess_signatures_are_counted() {
        let mut c = c();
        for i in 0..=MAX_SIGNERS {
            c.push(sig(1, &i.to_string()), 0);
        }
        assert_eq!(c.stats().excess_signatures, 1);
    }

    #[test]
    fn script_host_pairing_works_the_same() {
        let mut c = Correlator::new(SCRIPT_HOSTS, DEFAULT_WAIT);
        c.push(rec(8028, Some(1), &[("TotalSignatureCount", "1")]), 0);
        let out = c.push(rec(8038, Some(1), &[]), 1);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].record.event_id, 8028);
    }

    #[test]
    fn the_rate_limiter_bounds_bursts_and_refills() {
        let mut r = RateLimiter::new(10);
        let allowed = (0..20).filter(|_| r.allow(0)).count();
        assert_eq!(allowed, 10);
        assert_eq!(r.dropped(), 10);
        // A tenth of a second refills one record.
        assert!(r.allow(100_000));
        assert!(!r.allow(100_000));
        // A clock that goes backwards refills nothing.
        assert!(!r.allow(50_000));
        // A long pause refills only up to the burst.
        assert_eq!((0..30).filter(|_| r.allow(100_000_000)).count(), 10);
        let mut z = RateLimiter::new(0);
        assert!(z.allow(0));
        assert!(!z.allow(0));
    }
}
