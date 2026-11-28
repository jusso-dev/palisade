//! Renewal, rotation and expiry schedules (#224).
//!
//! These are pure functions of a validity window, the current time and, for
//! renewal, a caller-supplied random number. Nothing here reads a clock or a
//! random source, so every schedule can be tested by time travel.
//!
//! - [`RenewalPolicy`]: when a device certificate renews (at 2/3 of its
//!   lifetime, up to 10% earlier at random), how failed attempts back off
//!   (exponentially, up to 6 hours), and when a failing renewal alerts (less
//!   than 7 days left).
//! - [`ExpiryAlerts`]: the console's expiry alert thresholds (30, 14, 5 and 1
//!   days by default).
//! - [`RotationPlan`]: a key rotation with overlap: the new key is staged,
//!   the service switches to it, and the old key is removed after the
//!   overlap. Constructors enforce the minimum overlaps the issue sets for
//!   server TLS, issuing CA and unlock-token rotations.
//! - [`Adoption`]: how many devices report a trust version, which gates
//!   retiring an old policy-signing key.
//!
//! Every rule leans towards keeping the old key longer, or renewing earlier,
//! never the reverse (ADR 0018): a missing fact never shortens an overlap.

use std::fmt;
use std::time::Duration;

use crate::events::Timestamp;

use super::time::Validity;

const DAY: Duration = Duration::from_secs(86_400);

/// `duration` in whole microseconds, saturating at `i64::MAX`.
fn micros(duration: Duration) -> i64 {
    i64::try_from(duration.as_micros()).unwrap_or(i64::MAX)
}

/// `t + micros`, clamped to the timestamp range.
fn add(t: Timestamp, micros: i64) -> Timestamp {
    let sum = t
        .unix_micros()
        .saturating_add(micros)
        .clamp(Timestamp::MIN.unix_micros(), Timestamp::MAX.unix_micros());
    Timestamp::from_unix_micros(sum).unwrap_or(Timestamp::MAX)
}

/// `later - earlier` in microseconds. Never overflows: timestamps span less
/// than 2^59 microseconds.
fn span(earlier: Timestamp, later: Timestamp) -> i64 {
    later.unix_micros().saturating_sub(earlier.unix_micros())
}

/// How device certificates renew (#224).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenewalPolicy {
    initial_backoff: Duration,
    max_backoff: Duration,
    alert_window: Duration,
}

impl RenewalPolicy {
    /// Renew at 2/3 of the lifetime, retry after 1 minute doubling up to
    /// 6 hours, and alert when renewal is failing with less than 7 days left.
    pub const DEFAULT: Self = Self {
        initial_backoff: Duration::from_secs(60),
        max_backoff: Duration::from_secs(6 * 3600),
        alert_window: Duration::from_secs(7 * 86_400),
    };

    /// The fraction of the lifetime at which renewal is due, as
    /// numerator and denominator.
    pub const RENEW_AT: (i64, i64) = (2, 3);

    /// The most renewal may be brought forward at random, as a fraction of
    /// the lifetime (numerator, denominator).
    pub const MAX_JITTER: (i64, i64) = (1, 10);

    /// A policy with the given retry and alert settings.
    ///
    /// # Errors
    ///
    /// [`LifecycleError::BadBackoff`] if the initial back-off is zero or
    /// longer than the maximum.
    pub fn new(
        initial_backoff: Duration,
        max_backoff: Duration,
        alert_window: Duration,
    ) -> Result<Self, LifecycleError> {
        if initial_backoff.is_zero() || initial_backoff > max_backoff {
            return Err(LifecycleError::BadBackoff);
        }
        Ok(Self {
            initial_backoff,
            max_backoff,
            alert_window,
        })
    }

    /// When a certificate valid for `validity` should renew.
    ///
    /// That is 2/3 of the way through the lifetime, brought forward by up to
    /// 10% of the lifetime: `jitter` is a uniformly random `u32` from the
    /// caller, and the offset is `lifetime / 10 * jitter / 2^32`. Jitter
    /// only ever moves renewal earlier, so it spreads a fleet's renewals
    /// without ever leaving less time than the 2/3 point would.
    #[must_use]
    pub fn renewal_time(&self, validity: Validity, jitter: u32) -> Timestamp {
        let lifetime = i128::from(span(validity.not_before(), validity.not_after()));
        let (num, den) = Self::RENEW_AT;
        let base = lifetime * i128::from(num) / i128::from(den);
        let (jnum, jden) = Self::MAX_JITTER;
        let max_jitter = lifetime * i128::from(jnum) / i128::from(jden);
        let offset = (max_jitter * i128::from(jitter)) >> 32;
        // Both terms are between 0 and the lifetime, which fits an i64.
        let at = i64::try_from(base - offset).unwrap_or(0);
        add(validity.not_before(), at)
    }

    /// How long to wait before the next attempt after `failures` consecutive
    /// failed attempts: zero after none, then the initial back-off doubling
    /// each time, capped at the maximum.
    #[must_use]
    pub fn retry_delay(&self, failures: u32) -> Duration {
        if failures == 0 {
            return Duration::ZERO;
        }
        let shift = failures.saturating_sub(1).min(63);
        let factor = 1u64 << shift;
        let initial = u64::try_from(self.initial_backoff.as_millis()).unwrap_or(u64::MAX);
        let delay = Duration::from_millis(initial.saturating_mul(factor));
        delay.min(self.max_backoff)
    }

    /// Where a certificate stands at `now`, given its renewal time (from
    /// [`Self::renewal_time`]) and the number of consecutive failed renewal
    /// attempts.
    #[must_use]
    pub fn status(
        &self,
        validity: Validity,
        renew_at: Timestamp,
        now: Timestamp,
        failures: u32,
    ) -> RenewalStatus {
        if now > validity.not_after() {
            return RenewalStatus::Expired;
        }
        if now < renew_at {
            return RenewalStatus::Wait;
        }
        let remaining = span(now, validity.not_after());
        if failures > 0 && remaining < micros(self.alert_window) {
            RenewalStatus::Alert
        } else {
            RenewalStatus::Due
        }
    }
}

impl Default for RenewalPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Where a certificate stands in its renewal cycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenewalStatus {
    /// Renewal is not due yet.
    Wait,
    /// Renewal is due: try now, or after the retry delay.
    Due,
    /// Renewal is due, has been failing, and less than the alert window is
    /// left. Keep trying and raise an alert.
    Alert,
    /// The certificate has expired. It cannot renew itself: the device must
    /// re-enrol.
    Expired,
}

/// The expiry alert thresholds for certificates and keys (#224): 30, 14, 5
/// and 1 days by default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpiryAlerts {
    // Strictly descending, non-empty, every entry non-zero.
    thresholds: Vec<Duration>,
}

impl ExpiryAlerts {
    /// Most thresholds accepted.
    pub const MAX_THRESHOLDS: usize = 16;

    /// The default thresholds: 30, 14, 5 and 1 days.
    #[must_use]
    pub fn standard() -> Self {
        Self {
            thresholds: vec![DAY * 30, DAY * 14, DAY * 5, DAY],
        }
    }

    /// Custom thresholds, in any order.
    ///
    /// # Errors
    ///
    /// [`LifecycleError::BadThresholds`] if the list is empty, longer than
    /// [`Self::MAX_THRESHOLDS`], or holds a zero or a duplicate. An empty
    /// list would silence every expiry alert, so it is refused.
    pub fn new(thresholds: &[Duration]) -> Result<Self, LifecycleError> {
        if thresholds.is_empty() || thresholds.len() > Self::MAX_THRESHOLDS {
            return Err(LifecycleError::BadThresholds);
        }
        let mut sorted = thresholds.to_vec();
        sorted.sort_unstable_by(|a, b| b.cmp(a));
        let duplicate = sorted.windows(2).any(|w| w.first() == w.get(1));
        if duplicate || sorted.iter().any(Duration::is_zero) {
            return Err(LifecycleError::BadThresholds);
        }
        Ok(Self { thresholds: sorted })
    }

    /// The thresholds, longest first.
    #[must_use]
    pub fn thresholds(&self) -> &[Duration] {
        &self.thresholds
    }

    /// The alert for something that expires at `not_after`, seen at `now`.
    #[must_use]
    pub fn alert(&self, not_after: Timestamp, now: Timestamp) -> ExpiryAlert {
        let remaining = span(now, not_after);
        if remaining < 0 {
            return ExpiryAlert::Expired;
        }
        self.thresholds
            .iter()
            .rev()
            .find(|t| remaining <= micros(**t))
            .map_or(ExpiryAlert::None, |t| ExpiryAlert::Within(*t))
    }
}

impl Default for ExpiryAlerts {
    fn default() -> Self {
        Self::standard()
    }
}

/// An expiry alert level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpiryAlert {
    /// More time is left than the longest threshold.
    None,
    /// No more than this threshold is left: the shortest threshold crossed.
    Within(Duration),
    /// Already expired.
    Expired,
}

/// The stages of a rotation with overlap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationPhase {
    /// Before staging: only the old key is in use or published.
    Planned,
    /// The new key is published (pinned, listed) but the old key is still
    /// the one in use.
    Staged,
    /// The new key is in use. The old key is retiring and still trusted.
    Overlap,
    /// The old key may be removed from the trust set and retired.
    Complete,
}

/// A key rotation: stage the new key, switch to it, then remove the old one.
///
/// The constructors enforce a minimum lead (staging to switch) and a minimum
/// overlap (switch to removal), so a plan that would strand agents cannot be
/// built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotationPlan {
    staged_at: Timestamp,
    switch_at: Timestamp,
    retire_at: Timestamp,
}

impl RotationPlan {
    /// The least time a new server TLS key or certificate is pinned in the
    /// trust set before the server switches to it (#224).
    pub const SERVER_TLS_MIN_LEAD: Duration = Duration::from_secs(14 * 86_400);

    /// A plan with at least `min_lead` between staging and switching and at
    /// least `min_overlap` between switching and removing the old key.
    ///
    /// # Errors
    ///
    /// [`LifecycleError::LeadTooShort`] or [`LifecycleError::OverlapTooShort`].
    pub fn new(
        staged_at: Timestamp,
        switch_at: Timestamp,
        retire_at: Timestamp,
        min_lead: Duration,
        min_overlap: Duration,
    ) -> Result<Self, LifecycleError> {
        if span(staged_at, switch_at) < micros(min_lead) {
            return Err(LifecycleError::LeadTooShort);
        }
        if span(switch_at, retire_at) < micros(min_overlap) {
            return Err(LifecycleError::OverlapTooShort);
        }
        Ok(Self {
            staged_at,
            switch_at,
            retire_at,
        })
    }

    /// A server TLS rotation: the new pin is staged at least 14 days before
    /// the switch, and the old pin is removed no earlier than the switch.
    ///
    /// # Errors
    ///
    /// As [`Self::new`].
    pub fn server_tls(
        staged_at: Timestamp,
        switch_at: Timestamp,
        retire_at: Timestamp,
    ) -> Result<Self, LifecycleError> {
        Self::new(
            staged_at,
            switch_at,
            retire_at,
            Self::SERVER_TLS_MIN_LEAD,
            Duration::ZERO,
        )
    }

    /// An issuing CA rotation: the new CA issues from `switch_at`, and the
    /// old CA stays trusted for the longest device-certificate lifetime plus
    /// `grace`, so every certificate it issued expires or renews first.
    ///
    /// # Errors
    ///
    /// [`LifecycleError::LeadTooShort`] if `staged_at` is after `switch_at`.
    pub fn issuing_ca(
        staged_at: Timestamp,
        switch_at: Timestamp,
        max_cert_lifetime: Duration,
        grace: Duration,
    ) -> Result<Self, LifecycleError> {
        if switch_at < staged_at {
            return Err(LifecycleError::LeadTooShort);
        }
        // Clamped at the end of time, so an absurd overlap keeps the old CA
        // trusted rather than failing.
        let overlap = max_cert_lifetime.saturating_add(grace);
        Ok(Self {
            staged_at,
            switch_at,
            retire_at: add(switch_at, micros(overlap)),
        })
    }

    /// An unlock-token key rotation: tokens carry their `kid`, and the old
    /// key stays accepted until the longest-lived token it signed has
    /// expired.
    #[must_use]
    pub fn unlock_token(switch_at: Timestamp, max_token_lifetime: Duration) -> Self {
        Self {
            staged_at: switch_at,
            switch_at,
            retire_at: add(switch_at, micros(max_token_lifetime)),
        }
    }

    /// When the new key is published.
    #[must_use]
    pub const fn staged_at(&self) -> Timestamp {
        self.staged_at
    }

    /// When the new key comes into use.
    #[must_use]
    pub const fn switch_at(&self) -> Timestamp {
        self.switch_at
    }

    /// When the old key may be removed.
    #[must_use]
    pub const fn retire_at(&self) -> Timestamp {
        self.retire_at
    }

    /// The phase at `now`. Each boundary belongs to the later phase.
    #[must_use]
    pub fn phase(&self, now: Timestamp) -> RotationPhase {
        if now >= self.retire_at {
            RotationPhase::Complete
        } else if now >= self.switch_at {
            RotationPhase::Overlap
        } else if now >= self.staged_at {
            RotationPhase::Staged
        } else {
            RotationPhase::Planned
        }
    }
}

/// How many active devices report at least a target trust version (#224).
///
/// An old policy-signing key is retired only once every active device has
/// the trust set that lists its successor. A device that has not reported a
/// version counts as not adopted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Adoption {
    target: u64,
    adopted: usize,
    total: usize,
}

impl Adoption {
    /// Counts the devices whose reported trust version is at least `target`.
    /// `reported` has one entry per active device: `None` for a device that
    /// has not reported.
    pub fn measure<I>(target: u64, reported: I) -> Self
    where
        I: IntoIterator<Item = Option<u64>>,
    {
        let mut adopted = 0usize;
        let mut total = 0usize;
        for version in reported {
            total = total.saturating_add(1);
            if version.is_some_and(|v| v >= target) {
                adopted = adopted.saturating_add(1);
            }
        }
        Self {
            target,
            adopted,
            total,
        }
    }

    /// The target trust version.
    #[must_use]
    pub const fn target(&self) -> u64 {
        self.target
    }

    /// Devices at or past the target.
    #[must_use]
    pub const fn adopted(&self) -> usize {
        self.adopted
    }

    /// Active devices counted.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.total
    }

    /// Whether every active device has adopted the target, so the old key
    /// can be retired without stranding a device. True for an empty fleet.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.adopted == self.total
    }
}

/// A schedule value is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleError {
    /// The initial back-off is zero or longer than the maximum.
    BadBackoff,
    /// The alert thresholds are empty, too many, zero or duplicated.
    BadThresholds,
    /// The new key would be staged for less than the minimum lead time.
    LeadTooShort,
    /// The old key would be removed before the minimum overlap.
    OverlapTooShort,
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadBackoff => {
                f.write_str("the initial back-off must be non-zero and at most the maximum")
            }
            Self::BadThresholds => {
                f.write_str("expiry alert thresholds must be 1 to 16 distinct, non-zero durations")
            }
            Self::LeadTooShort => {
                f.write_str("the new key would be staged for less than the minimum lead time")
            }
            Self::OverlapTooShort => {
                f.write_str("the old key would be removed before the minimum overlap")
            }
        }
    }
}

impl std::error::Error for LifecycleError {}
