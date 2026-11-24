//! Hashing and cache counters, for health reporting (#46, #67).

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Counters updated by the hash cache and [`super::cache::hash_through`].
/// Every counter only goes up; read them with [`Self::snapshot`].
#[derive(Debug, Default)]
pub struct HashMetrics {
    bytes_hashed: AtomicU64,
    hashes: AtomicU64,
    hash_nanos: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
    tamper_events: AtomicU64,
    unstable: AtomicU64,
}

/// The counters at one moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HashMetricsSnapshot {
    /// Bytes read and hashed.
    pub bytes_hashed: u64,
    /// Files hashed (each attempt counts, including ones thrown away
    /// because the file changed).
    pub hashes: u64,
    /// Total time spent hashing.
    pub hash_time: Duration,
    /// Cache lookups that returned a value.
    pub hits: u64,
    /// Cache lookups that did not.
    pub misses: u64,
    /// Entries evicted to stay within the cache's bounds.
    pub evictions: u64,
    /// Persisted records rejected because their MAC did not verify.
    pub tamper_events: u64,
    /// Files that kept changing while they were hashed.
    pub unstable: u64,
}

impl HashMetricsSnapshot {
    /// Hits over lookups, from 0.0 to 1.0. `None` before any lookup.
    #[must_use]
    pub fn hit_ratio(&self) -> Option<f64> {
        let lookups = self.hits.saturating_add(self.misses);
        (lookups > 0).then(|| to_f64(self.hits) / to_f64(lookups))
    }

    /// The mean time per hash. `None` before any hash.
    #[must_use]
    pub fn average_latency(&self) -> Option<Duration> {
        (self.hashes > 0).then(|| {
            let nanos = self.hash_time.as_nanos() / u128::from(self.hashes);
            Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
        })
    }
}

#[allow(clippy::cast_precision_loss)] // A ratio needs no exact counts.
const fn to_f64(n: u64) -> f64 {
    n as f64
}

impl HashMetrics {
    /// The counters now.
    #[must_use]
    pub fn snapshot(&self) -> HashMetricsSnapshot {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        HashMetricsSnapshot {
            bytes_hashed: get(&self.bytes_hashed),
            hashes: get(&self.hashes),
            hash_time: Duration::from_nanos(get(&self.hash_nanos)),
            hits: get(&self.hits),
            misses: get(&self.misses),
            evictions: get(&self.evictions),
            tamper_events: get(&self.tamper_events),
            unstable: get(&self.unstable),
        }
    }

    /// Records one hash of `bytes` bytes that took `elapsed`.
    pub fn record_hash(&self, bytes: u64, elapsed: Duration) {
        add(&self.bytes_hashed, bytes);
        add(&self.hashes, 1);
        add(
            &self.hash_nanos,
            u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX),
        );
    }

    pub(crate) fn record_hit(&self) {
        add(&self.hits, 1);
    }

    pub(crate) fn record_miss(&self) {
        add(&self.misses, 1);
    }

    pub(crate) fn record_eviction(&self) {
        add(&self.evictions, 1);
    }

    pub(crate) fn record_tamper(&self) {
        add(&self.tamper_events, 1);
    }

    pub(crate) fn record_unstable(&self) {
        add(&self.unstable, 1);
    }
}

/// Adds without wrapping: a counter stops at `u64::MAX`.
fn add(counter: &AtomicU64, n: u64) {
    // A compare-exchange loop: `fetch_update` is deprecated on the pinned
    // toolchain, and this works on every supported one.
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        match counter.compare_exchange_weak(
            current,
            current.saturating_add(n),
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}
