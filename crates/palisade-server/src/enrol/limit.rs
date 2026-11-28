//! Fixed-window rate limits for the enrolment endpoint (#223): per source
//! address (default 10 a minute) and per registration code (default 100 an
//! hour).
//!
//! A window starts at a key's first request and lasts `window`; within it at
//! most `max` requests pass. The table is bounded: when it is full, expired
//! windows are dropped, and if none has expired the request is refused, so
//! a flood of distinct keys cannot grow memory or open the gate.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::Duration;

use palisade_proto::events::Timestamp;

/// The most keys one limiter tracks.
pub const MAX_KEYS: usize = 65_536;

/// One limiter.
#[derive(Debug)]
pub struct Limiter<K> {
    max: u32,
    window_micros: i64,
    windows: Mutex<HashMap<K, (Timestamp, u32)>>,
}

impl<K: Eq + Hash + Clone> Limiter<K> {
    /// At most `max` requests per key in each `window`.
    #[must_use]
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            max,
            window_micros: i64::try_from(window.as_micros()).unwrap_or(i64::MAX),
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Counts a request for `key` at `now`. Returns `Err(retry_after)` when
    /// it is over the limit.
    ///
    /// # Errors
    ///
    /// The time until the key's window ends.
    pub fn check(&self, key: &K, now: Timestamp) -> Result<(), Duration> {
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let expired = |start: Timestamp| {
            now.unix_micros().saturating_sub(start.unix_micros()) >= self.window_micros
        };
        if !windows.contains_key(key) && windows.len() >= MAX_KEYS {
            windows.retain(|_, (start, _)| !expired(*start));
            if windows.len() >= MAX_KEYS {
                return Err(Duration::from_micros(
                    u64::try_from(self.window_micros).unwrap_or(0),
                ));
            }
        }
        let entry = windows.entry(key.clone()).or_insert((now, 0));
        if expired(entry.0) {
            *entry = (now, 0);
        }
        if entry.1 >= self.max {
            let left = self
                .window_micros
                .saturating_sub(now.unix_micros().saturating_sub(entry.0.unix_micros()));
            return Err(Duration::from_micros(u64::try_from(left).unwrap_or(0)));
        }
        entry.1 += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: i64) -> Timestamp {
        Timestamp::from_unix_micros(s * 1_000_000).unwrap()
    }

    #[test]
    fn the_window_allows_max_then_refuses_until_it_ends() {
        let l = Limiter::new(2, Duration::from_secs(60));
        assert!(l.check(&1, ts(0)).is_ok());
        assert!(l.check(&1, ts(1)).is_ok());
        assert_eq!(l.check(&1, ts(10)), Err(Duration::from_secs(50)));
        // Another key has its own window.
        assert!(l.check(&2, ts(10)).is_ok());
        // The window ends 60 s after it started.
        assert!(l.check(&1, ts(60)).is_ok());
    }

    #[test]
    fn a_full_table_drops_expired_windows_and_otherwise_refuses() {
        let l = Limiter::new(1, Duration::from_secs(60));
        for k in 0..MAX_KEYS {
            assert!(l.check(&k, ts(0)).is_ok());
        }
        assert!(l.check(&MAX_KEYS, ts(1)).is_err());
        assert!(l.check(&MAX_KEYS, ts(60)).is_ok());
    }
}
