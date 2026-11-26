//! Staleness (#225, ADR 0018 "Policy stale or past `expires_at`").
//!
//! A policy is stale when no new bundle was received within
//! `policy.stale_after` (7 days by default), or when `now` is past the
//! bundle's `expires_at`. Staleness is only reported: the agent keeps
//! enforcing the bundle it runs. This module returns a report and nothing
//! that could change what loads, so it cannot relax enforcement.
//!
//! `now` must be trusted time on the agent (#220), never the raw wall clock.

use std::time::Duration;

use crate::events::{EventType, Timestamp};

/// `policy.stale_after`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StaleAfter(i64);

const MICROS_PER_DAY: i64 = 86_400 * 1_000_000;

impl StaleAfter {
    /// 7 days, the default.
    pub const DEFAULT: Self = Self(7 * MICROS_PER_DAY);

    /// A window of `duration`, truncated to whole microseconds. Durations
    /// too large for a timestamp are capped, which only delays the report.
    #[must_use]
    pub fn new(duration: Duration) -> Self {
        Self(i64::try_from(duration.as_micros()).unwrap_or(i64::MAX))
    }

    /// The window in microseconds.
    #[must_use]
    pub const fn as_micros(self) -> i64 {
        self.0
    }
}

impl Default for StaleAfter {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Why a policy is stale.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Staleness {
    /// No bundle was received within the window.
    pub not_refreshed: bool,
    /// `now` is past `expires_at`.
    pub expired: bool,
}

impl Staleness {
    /// Whether the policy is stale for either reason.
    #[must_use]
    pub const fn is_stale(self) -> bool {
        self.not_refreshed || self.expired
    }

    /// `policy.stale` when stale. The agent keeps enforcing either way.
    #[must_use]
    pub const fn event_type(self) -> Option<EventType> {
        if self.is_stale() {
            Some(EventType::PolicyStale)
        } else {
            None
        }
    }
}

/// Whether the policy in force is stale at `now`.
///
/// `last_received` is when the agent last received a verified bundle (or
/// confirmed that its bundle is current), and `expires_at` is the running
/// bundle's optional expiry. Both bounds are exclusive: a bundle becomes
/// stale strictly after `last_received + stale_after`, and strictly after
/// `expires_at`.
#[must_use]
pub fn check(
    now: Timestamp,
    last_received: Timestamp,
    stale_after: StaleAfter,
    expires_at: Option<Timestamp>,
) -> Staleness {
    let now = now.unix_micros();
    Staleness {
        not_refreshed: now.saturating_sub(last_received.unix_micros()) > stale_after.0,
        expired: expires_at.is_some_and(|e| now > e.unix_micros()),
    }
}
