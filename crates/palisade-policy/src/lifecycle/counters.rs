//! Per-rule hit counters (#40).
//!
//! [`Counters`] holds one slot per rule of an [`Evaluator`], indexed by the
//! rule's ordinal (its position in the evaluator), so recording a hit is
//! one relaxed atomic add, with no lock and no allocation. The last match
//! time and the sketch registers are read first and written only when the
//! value grows, which after warm-up is rare. The agent
//! records every terminal match and annotation ([`Counters::record`]) and
//! takes a [`HitReport`] every `counter_report_hours` and on a policy
//! change ([`Counters::report`]).
//!
//! Counters belong to one bundle revision. A report carries the policy ID
//! and revision, and the server adds reports up across revisions by rule
//! ID. To survive an agent restart, the agent stores the last report it
//! took and [`Counters::restore`]s it into the new counters of the same
//! revision. The totals then carry on, and nothing is reported twice.
//!
//! `distinct_objects` is a HyperLogLog sketch with 1024 one-byte registers
//! (1 KiB, a standard error of about 3%), updated with atomic maximums.
//! `distinct_devices` is the server's sum of these sketches across devices
//! (#10), so it is not kept here.
//!
//! [`Evaluator`]: crate::evaluate::Evaluator

use std::sync::atomic::{AtomicI64, AtomicU8, AtomicU64, Ordering};

use serde::Serialize;

use crate::decision::{Decision, RuleRef};
use crate::model::{PolicyId, RuleId, Timestamp};

/// HyperLogLog registers per rule: 2^10.
const HLL_BITS: u32 = 10;
const HLL_REGISTERS: usize = 1 << HLL_BITS;

/// A HyperLogLog sketch of distinct objects, updated without a lock.
#[derive(Debug)]
struct Sketch {
    registers: Box<[AtomicU8]>,
}

impl Sketch {
    fn new() -> Self {
        Self {
            registers: (0..HLL_REGISTERS).map(|_| AtomicU8::new(0)).collect(),
        }
    }

    fn add(&self, hash: u64) {
        // The top bits choose the register, the rest give the rank.
        let index = usize::try_from(hash >> (64 - HLL_BITS)).unwrap_or(0);
        let rest = (hash << HLL_BITS) | (1 << (HLL_BITS - 1));
        let rank = u8::try_from(rest.leading_zeros() + 1).unwrap_or(u8::MAX);
        if let Some(r) = self.registers.get(index) {
            if r.load(Ordering::Relaxed) < rank {
                r.fetch_max(rank, Ordering::Relaxed);
            }
        }
    }

    fn snapshot(&self) -> Vec<u8> {
        self.registers
            .iter()
            .map(|r| r.load(Ordering::Relaxed))
            .collect()
    }

    fn restore(&self, registers: &[u8]) {
        for (r, v) in self.registers.iter().zip(registers) {
            r.fetch_max(*v, Ordering::Relaxed);
        }
    }

    fn clear(&self) {
        for r in &*self.registers {
            r.store(0, Ordering::Relaxed);
        }
    }
}

/// The HyperLogLog estimate of a set of registers, with the small-range
/// correction.
#[must_use]
pub fn estimate(registers: &[u8]) -> u64 {
    let m = f64::from(u32::try_from(registers.len()).unwrap_or(u32::MAX));
    if registers.is_empty() {
        return 0;
    }
    let alpha = 0.7213 / (1.0 + 1.079 / m);
    let sum: f64 = registers.iter().map(|r| 2f64.powi(-i32::from(*r))).sum();
    let raw = alpha * m * m / sum;
    let zeros = registers.iter().filter(|r| **r == 0).count();
    let value = if raw <= 2.5 * m && zeros > 0 {
        m * (m / f64::from(u32::try_from(zeros).unwrap_or(u32::MAX))).ln()
    } else {
        raw
    };
    // The estimate is non-negative and far below 2^53.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let n = value.round() as u64;
    n
}

/// The key [`Counters::hit_key`] takes for an object: a 64-bit hash of its
/// identifier (its SHA-256, for example). FNV-1a, then a finaliser, so any
/// identifier spreads evenly over the sketch's registers.
#[must_use]
pub fn object_key(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    // splitmix64 finaliser.
    h ^= h >> 30;
    h = h.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    h ^= h >> 27;
    h = h.wrapping_mul(0x94d0_49bb_1331_11eb);
    h ^ (h >> 31)
}

/// One rule's slot.
#[derive(Debug)]
struct Slot {
    rule: RuleRef,
    total: AtomicU64,
    /// `total` at the previous report.
    reported: AtomicU64,
    /// Seconds since 1970 of the last match, or `i64::MIN` for none.
    last_matched: AtomicI64,
    objects: Sketch,
}

/// The hit counters of one evaluator's rules.
#[derive(Debug)]
pub struct Counters {
    policy_id: PolicyId,
    revision: u64,
    slots: Vec<Slot>,
}

/// One rule's counters in a report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleHits {
    /// The rule.
    pub rule_id: RuleId,
    /// Hits since the counters were created (or restored from).
    pub hits_total: u64,
    /// Hits since the previous report.
    pub hits_since_report: u64,
    /// The last match, if any.
    pub last_matched_at: Option<Timestamp>,
    /// The estimated number of distinct objects matched.
    pub distinct_objects: u64,
    /// The sketch's registers, for the server to merge across devices.
    #[serde(skip)]
    pub sketch: Vec<u8>,
}

/// A report of every rule's counters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HitReport {
    /// The policy.
    pub policy_id: PolicyId,
    /// The bundle revision the counters belong to.
    pub revision: u64,
    /// When the report was taken.
    pub at: Timestamp,
    /// Every rule with at least one hit, by rule ID.
    pub rules: Vec<RuleHits>,
}

impl Counters {
    /// Counters for `rules`, in the evaluator's ordinal order.
    pub(crate) fn new(policy_id: PolicyId, revision: u64, rules: Vec<RuleRef>) -> Self {
        Self {
            policy_id,
            revision,
            slots: rules
                .into_iter()
                .map(|rule| Slot {
                    rule,
                    total: AtomicU64::new(0),
                    reported: AtomicU64::new(0),
                    last_matched: AtomicI64::new(i64::MIN),
                    objects: Sketch::new(),
                })
                .collect(),
        }
    }

    /// How many rules are counted.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether no rules are counted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// The ordinal of a rule, if it is counted.
    #[must_use]
    pub fn ordinal(&self, rule_id: RuleId) -> Option<usize> {
        self.slots.iter().position(|s| s.rule.rule_id == rule_id)
    }

    /// Records one hit of the rule at `ordinal`, on the object identified
    /// by `object` (its SHA-256, for example), at `at`. An ordinal out of
    /// range is ignored.
    pub fn hit(&self, ordinal: usize, object: &[u8], at: Timestamp) {
        self.hit_key(ordinal, object_key(object), at);
    }

    /// The same as [`hit`](Self::hit), with the object's key already
    /// computed ([`object_key`]), as the agent does once per object.
    #[inline]
    pub fn hit_key(&self, ordinal: usize, key: u64, at: Timestamp) {
        let Some(slot) = self.slots.get(ordinal) else {
            return;
        };
        slot.total.fetch_add(1, Ordering::Relaxed);
        if slot.last_matched.load(Ordering::Relaxed) < at.0 {
            slot.last_matched.fetch_max(at.0, Ordering::Relaxed);
        }
        slot.objects.add(key);
    }

    /// Records the deciding rule and every annotation of `decision`. A
    /// decision of another policy or revision records nothing.
    pub fn record(&self, decision: &Decision, object: &[u8], at: Timestamp) {
        let refs = decision
            .matched_rule()
            .into_iter()
            .chain(decision.annotations());
        for r in refs {
            if r.policy_id != self.policy_id || r.policy_revision != self.revision {
                continue;
            }
            if let Some(i) = self.slots.iter().position(|s| s.rule == *r) {
                self.hit(i, object, at);
            }
        }
    }

    /// Takes a report at `at`, and starts a new `hits_since_report` period.
    pub fn report(&self, at: Timestamp) -> HitReport {
        let mut rules: Vec<RuleHits> = self
            .slots
            .iter()
            .filter_map(|s| {
                let total = s.total.load(Ordering::Relaxed);
                let since = total.saturating_sub(s.reported.swap(total, Ordering::Relaxed));
                (total > 0).then(|| {
                    let sketch = s.objects.snapshot();
                    let last = s.last_matched.load(Ordering::Relaxed);
                    RuleHits {
                        rule_id: s.rule.rule_id,
                        hits_total: total,
                        hits_since_report: since,
                        last_matched_at: (last != i64::MIN).then_some(Timestamp(last)),
                        distinct_objects: estimate(&sketch),
                        sketch,
                    }
                })
            })
            .collect();
        rules.sort_by_key(|r| r.rule_id);
        HitReport {
            policy_id: self.policy_id,
            revision: self.revision,
            at,
            rules,
        }
    }

    /// Restores the totals, last match times and sketches of `report`, the
    /// last report taken before a restart, if it is of the same policy and
    /// revision. `hits_since_report` starts at zero, because those hits
    /// were reported. Returns whether it was restored.
    pub fn restore(&self, report: &HitReport) -> bool {
        if report.policy_id != self.policy_id || report.revision != self.revision {
            return false;
        }
        for r in &report.rules {
            if let Some(slot) = self.slots.iter().find(|s| s.rule.rule_id == r.rule_id) {
                // Those hits were reported already.
                slot.total.fetch_add(r.hits_total, Ordering::Relaxed);
                slot.reported.fetch_add(r.hits_total, Ordering::Relaxed);
                if let Some(t) = r.last_matched_at {
                    slot.last_matched.fetch_max(t.0, Ordering::Relaxed);
                }
                slot.objects.restore(&r.sketch);
            }
        }
        true
    }

    /// Clears every counter.
    pub fn clear(&self) {
        for s in &self.slots {
            s.total.store(0, Ordering::Relaxed);
            s.reported.store(0, Ordering::Relaxed);
            s.last_matched.store(i64::MIN, Ordering::Relaxed);
            s.objects.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refs(n: u8) -> Vec<RuleRef> {
        let policy: PolicyId = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f".parse().unwrap();
        (0..n)
            .map(|i| RuleRef {
                rule_id: format!("01936b2e-{i:04x}-7b3d-9f21-0a1b2c3d4e61")
                    .parse()
                    .unwrap(),
                display_id: None,
                rule_set_id: "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001".parse().unwrap(),
                policy_id: policy,
                policy_revision: 4,
            })
            .collect()
    }

    fn counters(n: u8) -> Counters {
        let r = refs(n);
        Counters::new(r[0].policy_id, 4, r)
    }

    #[test]
    fn hits_totals_and_last_match() {
        let c = counters(3);
        c.hit(1, b"a", Timestamp(10));
        c.hit(1, b"a", Timestamp(5));
        c.hit(1, b"b", Timestamp(20));
        c.hit(9, b"x", Timestamp(30));
        let r = c.report(Timestamp(100));
        assert_eq!(r.rules.len(), 1);
        let h = &r.rules[0];
        assert_eq!((h.hits_total, h.hits_since_report), (3, 3));
        assert_eq!(h.last_matched_at, Some(Timestamp(20)));
        assert_eq!(h.distinct_objects, 2);
        c.hit(1, b"c", Timestamp(40));
        let r = c.report(Timestamp(200));
        assert_eq!(
            (r.rules[0].hits_total, r.rules[0].hits_since_report),
            (4, 1)
        );
    }

    #[test]
    fn a_restart_restores_the_last_report() {
        let c = counters(2);
        for i in 0..50u32 {
            c.hit(0, &i.to_le_bytes(), Timestamp(i64::from(i)));
        }
        let saved = c.report(Timestamp(100));
        // A restart: new counters of the same revision.
        let after = counters(2);
        assert!(after.restore(&saved));
        after.hit(0, b"new", Timestamp(200));
        let r = after.report(Timestamp(300));
        assert_eq!(r.rules[0].hits_total, 51);
        assert_eq!(r.rules[0].hits_since_report, 1);
        assert_eq!(r.rules[0].last_matched_at, Some(Timestamp(200)));
        assert!(r.rules[0].distinct_objects >= 49);
        // Another revision does not restore.
        let other = Counters::new(refs(1)[0].policy_id, 5, refs(1));
        assert!(!other.restore(&saved));
    }

    #[test]
    fn the_sketch_estimates_within_a_few_percent() {
        let c = counters(1);
        for i in 0..20_000u32 {
            c.hit(0, &i.to_le_bytes(), Timestamp(0));
        }
        let n = c.report(Timestamp(0)).rules[0].distinct_objects;
        assert!((18_800..=21_200).contains(&n), "{n}");
        assert_eq!(c.slots[0].objects.registers.len(), 1024);
    }

    #[test]
    fn counters_are_shared_across_threads() {
        let c = std::sync::Arc::new(counters(1));
        let handles: Vec<_> = (0..4u8)
            .map(|t| {
                let c = c.clone();
                std::thread::spawn(move || {
                    for i in 0..1000u32 {
                        c.hit(0, &[t, (i % 7) as u8], Timestamp(i64::from(i)));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(c.report(Timestamp(0)).rules[0].hits_total, 4000);
    }
}
