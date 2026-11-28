//! The per-agent event quota (#197).
//!
//! The quota counts the events the pipeline keeps per hour (default
//! 50,000), in a sliding window of one-minute buckets. Crossing the high
//! watermark (80%) switches summarisable allowed events to summaries
//! (`agent.throttled`), until the count falls below the low watermark
//! (50%). Over the quota, events that may be summarised or dropped
//! (allowed events in full, diagnostics) are dropped and counted; events
//! that may not (blocked, audited, security, information) are never
//! dropped: they raise `agent.throttle_exceeded` once per episode, as an
//! alert, and are kept (#197). A throttle storm of allowed events
//! therefore never suppresses a blocked event.

#![forbid(unsafe_code)]

use std::collections::VecDeque;

use super::segment::Class;

/// The throttle's settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThrottleSettings {
    /// Events per hour. 0 turns the throttle off.
    pub per_hour: u64,
    /// The high watermark, in percent of `per_hour`.
    pub high_percent: u8,
    /// The low watermark, in percent of `per_hour`.
    pub low_percent: u8,
}

impl Default for ThrottleSettings {
    fn default() -> Self {
        Self {
            per_hour: 50_000,
            high_percent: 80,
            low_percent: 50,
        }
    }
}

/// What the throttle says about one event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admit {
    /// Keep it.
    Keep,
    /// Drop it, and count it.
    Drop,
}

/// A change of throttle state, for the pipeline to report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transition {
    /// The high watermark was crossed: eligible events are summarised.
    Throttling,
    /// The count fell below the low watermark again.
    Normal,
    /// The quota was exceeded by events that are never dropped.
    Exceeded,
}

const BUCKET_MICROS: i64 = 60 * 1_000_000;
const BUCKETS: usize = 60;

/// The throttle.
#[derive(Clone, Debug)]
pub struct Throttle {
    settings: ThrottleSettings,
    /// (minute, count), oldest first, covering the last hour.
    buckets: VecDeque<(i64, u64)>,
    total: u64,
    throttling: bool,
    exceeded: bool,
    transitions: Vec<Transition>,
    dropped: u64,
}

impl Throttle {
    /// A throttle with `settings`.
    #[must_use]
    pub fn new(settings: ThrottleSettings) -> Self {
        Self {
            settings,
            buckets: VecDeque::with_capacity(BUCKETS + 1),
            total: 0,
            throttling: false,
            exceeded: false,
            transitions: Vec::new(),
            dropped: 0,
        }
    }

    fn threshold(&self, percent: u8) -> u64 {
        let t = u128::from(self.settings.per_hour) * u128::from(percent) / 100;
        u64::try_from(t).unwrap_or(u64::MAX)
    }

    fn advance(&mut self, now: i64) {
        let minute = now.div_euclid(BUCKET_MICROS);
        while let Some(&(m, n)) = self.buckets.front() {
            // Keep the last hour; a clock that went back keeps everything.
            if minute.saturating_sub(m) >= i64::try_from(BUCKETS).unwrap_or(i64::MAX) {
                self.buckets.pop_front();
                self.total = self.total.saturating_sub(n);
            } else {
                break;
            }
        }
        if self.throttling && self.total < self.threshold(self.settings.low_percent) {
            self.throttling = false;
            self.exceeded = false;
            self.transitions.push(Transition::Normal);
        }
    }

    fn count(&mut self, now: i64) {
        let minute = now.div_euclid(BUCKET_MICROS);
        match self.buckets.back_mut() {
            Some((m, n)) if *m >= minute => *n = n.saturating_add(1),
            _ => self.buckets.push_back((minute, 1)),
        }
        self.total = self.total.saturating_add(1);
        if !self.throttling && self.total >= self.threshold(self.settings.high_percent) {
            self.throttling = true;
            self.transitions.push(Transition::Throttling);
        }
    }

    /// Decides about one event of `class`, which happened at `now`
    /// (microseconds since the epoch), and counts it if it is kept.
    pub fn admit(&mut self, class: Class, now: i64) -> Admit {
        if self.settings.per_hour == 0 {
            return Admit::Keep;
        }
        self.advance(now);
        let droppable = matches!(class, Class::Diagnostic | Class::Allowed);
        if self.total >= self.settings.per_hour {
            if droppable {
                self.dropped = self.dropped.saturating_add(1);
                return Admit::Drop;
            }
            if !self.exceeded && class != Class::Summary {
                self.exceeded = true;
                self.transitions.push(Transition::Exceeded);
            }
        }
        self.count(now);
        Admit::Keep
    }

    /// The state changes since the last call.
    pub fn take_transitions(&mut self) -> Vec<Transition> {
        std::mem::take(&mut self.transitions)
    }

    /// Whether eligible events are being summarised: the pipeline then
    /// folds every summarisable allowed event into a summary, whatever the
    /// allowed-events mode.
    #[must_use]
    pub const fn is_throttling(&self) -> bool {
        self.throttling
    }

    /// Events dropped since the last call.
    pub fn take_dropped(&mut self) -> u64 {
        std::mem::take(&mut self.dropped)
    }

    /// Events counted in the last hour.
    #[must_use]
    pub const fn count_last_hour(&self) -> u64 {
        self.total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: i64 = BUCKET_MICROS;

    fn throttle(per_hour: u64) -> Throttle {
        Throttle::new(ThrottleSettings {
            per_hour,
            ..ThrottleSettings::default()
        })
    }

    #[test]
    fn watermarks_switch_to_summaries_and_back() {
        let mut t = throttle(10);
        for _ in 0..7 {
            assert_eq!(t.admit(Class::Allowed, 0), Admit::Keep);
        }
        assert!(t.take_transitions().is_empty());
        // The 8th event reaches 80%.
        assert_eq!(t.admit(Class::Allowed, 0), Admit::Keep);
        assert_eq!(t.take_transitions(), [Transition::Throttling]);
        assert!(t.is_throttling());
        assert_eq!(t.admit(Class::Blocked, 0), Admit::Keep);
        assert_eq!(t.admit(Class::Allowed, 0), Admit::Keep);
        // Full: allowed and diagnostic events are dropped and counted.
        assert_eq!(t.admit(Class::Allowed, 0), Admit::Drop);
        assert_eq!(t.admit(Class::Diagnostic, 0), Admit::Drop);
        assert_eq!(t.take_dropped(), 2);
        assert_eq!(t.take_dropped(), 0);
        // A blocked event is never dropped; it raises one alert.
        assert_eq!(t.admit(Class::Blocked, MIN), Admit::Keep);
        assert_eq!(t.admit(Class::Security, MIN), Admit::Keep);
        assert_eq!(t.admit(Class::Summary, MIN), Admit::Keep);
        assert_eq!(t.take_transitions(), [Transition::Exceeded]);
        assert_eq!(t.count_last_hour(), 13);
        // An hour later the window has emptied: back to normal.
        assert_eq!(t.admit(Class::Allowed, 61 * MIN), Admit::Keep);
        assert_eq!(t.take_transitions(), [Transition::Normal]);
        assert!(!t.is_throttling());
        assert_eq!(t.count_last_hour(), 1);
    }

    #[test]
    fn the_window_slides_by_the_minute() {
        let mut t = throttle(100);
        for minute in 0..60 {
            t.admit(Class::Info, minute * MIN);
        }
        assert_eq!(t.count_last_hour(), 60);
        t.admit(Class::Info, 60 * MIN);
        assert_eq!(t.count_last_hour(), 60, "minute 0 left the window");
        // A clock that went back keeps counting in the newest bucket.
        t.admit(Class::Info, 10 * MIN);
        assert_eq!(t.count_last_hour(), 61);
    }

    #[test]
    fn zero_turns_it_off() {
        let mut t = throttle(0);
        for _ in 0..1000 {
            assert_eq!(t.admit(Class::Allowed, 0), Admit::Keep);
        }
        assert_eq!(t.count_last_hour(), 0);
        assert_eq!(
            ThrottleSettings::default(),
            ThrottleSettings {
                per_hour: 50_000,
                high_percent: 80,
                low_percent: 50
            }
        );
    }
}
