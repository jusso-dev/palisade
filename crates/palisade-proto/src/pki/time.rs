//! Validity windows, clock-skew tolerance and the injectable clock.
//!
//! Every certificate, key and token validity check in `pki` goes through
//! [`Validity::check`], which allows a bounded clock-skew tolerance (default
//! 5 minutes, #224). The caller supplies `now`: on the agent that must be
//! trusted time (#220), never the raw wall clock, so a clock rolled back by
//! a local administrator cannot revive an expired key.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::events::Timestamp;

/// A source of the current time. Tests inject a fixed clock.
pub trait Clock {
    /// The current time.
    fn now(&self) -> Timestamp;
}

/// The operating system's wall clock.
///
/// Fine on the server, whose time is synchronised (#224). The agent passes
/// trusted time (#220) instead.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let micros = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(after) => i64::try_from(after.as_micros()).unwrap_or(i64::MAX),
            Err(before) => i64::try_from(before.duration().as_micros())
                .map_or(i64::MIN, |m| m.saturating_neg()),
        };
        Timestamp::from_unix_micros(
            micros.clamp(Timestamp::MIN.unix_micros(), Timestamp::MAX.unix_micros()),
        )
        .unwrap_or(Timestamp::MIN)
    }
}

/// A clock that always returns the same instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedClock(pub Timestamp);

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        self.0
    }
}

/// How far the local clock may be from true time before validity checks
/// fail: from zero to [`SkewTolerance::MAX`], 5 minutes by default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SkewTolerance(i64);

const MICROS_PER_SECOND: i64 = 1_000_000;

impl SkewTolerance {
    /// No tolerance.
    pub const ZERO: Self = Self(0);
    /// 5 minutes, the default (#224, matching `tamper.clock.skew` in #220).
    pub const DEFAULT: Self = Self(5 * 60 * MICROS_PER_SECOND);
    /// 1 hour. A larger tolerance would make short-lived certificates and
    /// tokens meaningless, so it is refused.
    pub const MAX: Self = Self(60 * 60 * MICROS_PER_SECOND);

    /// A tolerance of `duration`, truncated to whole microseconds.
    ///
    /// # Errors
    ///
    /// [`TimeError::SkewTooLarge`] above [`Self::MAX`].
    pub fn new(duration: Duration) -> Result<Self, TimeError> {
        let micros = i64::try_from(duration.as_micros()).map_err(|_| TimeError::SkewTooLarge)?;
        if micros > Self::MAX.0 {
            return Err(TimeError::SkewTooLarge);
        }
        Ok(Self(micros))
    }

    /// The tolerance in microseconds.
    #[must_use]
    pub const fn as_micros(self) -> i64 {
        self.0
    }
}

impl Default for SkewTolerance {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A closed validity window: valid from `not_before` to `not_after`, both
/// inclusive, as in X.509.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Validity {
    not_before: Timestamp,
    not_after: Timestamp,
}

impl Validity {
    /// A window from `not_before` to `not_after`.
    ///
    /// # Errors
    ///
    /// [`TimeError::EmptyWindow`] if `not_after` is before `not_before`.
    pub fn new(not_before: Timestamp, not_after: Timestamp) -> Result<Self, TimeError> {
        if not_after < not_before {
            return Err(TimeError::EmptyWindow);
        }
        Ok(Self {
            not_before,
            not_after,
        })
    }

    /// The first valid instant.
    #[must_use]
    pub const fn not_before(&self) -> Timestamp {
        self.not_before
    }

    /// The last valid instant.
    #[must_use]
    pub const fn not_after(&self) -> Timestamp {
        self.not_after
    }

    /// Whether `now` is inside the window, with no skew allowance.
    #[must_use]
    pub fn contains(&self, now: Timestamp) -> bool {
        self.not_before <= now && now <= self.not_after
    }

    /// Checks the window at `now`, allowing `skew` on either side: valid
    /// when `not_before - skew <= now <= not_after + skew`.
    ///
    /// # Errors
    ///
    /// [`TimeError::NotYetValid`] or [`TimeError::Expired`].
    pub fn check(&self, now: Timestamp, skew: SkewTolerance) -> Result<(), TimeError> {
        // Microsecond arithmetic on i64 cannot overflow here: timestamps are
        // within years 1 to 9999 (about ±2.6e17) and the skew is at most 1 h.
        let now = now.unix_micros();
        if now.saturating_add(skew.0) < self.not_before.unix_micros() {
            return Err(TimeError::NotYetValid {
                not_before: self.not_before,
            });
        }
        if now.saturating_sub(skew.0) > self.not_after.unix_micros() {
            return Err(TimeError::Expired {
                not_after: self.not_after,
            });
        }
        Ok(())
    }

    /// Whether `instant` is no later than `now + skew`: used to refuse data
    /// stamped in the future.
    pub(crate) fn not_in_future(instant: Timestamp, now: Timestamp, skew: SkewTolerance) -> bool {
        instant.unix_micros() <= now.unix_micros().saturating_add(skew.0)
    }
}

/// A time value or check is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeError {
    /// `not_after` is before `not_before`.
    EmptyWindow,
    /// The skew tolerance is above [`SkewTolerance::MAX`].
    SkewTooLarge,
    /// Not valid until `not_before`, even allowing for skew.
    NotYetValid {
        /// The first valid instant.
        not_before: Timestamp,
    },
    /// Expired at `not_after`, even allowing for skew.
    Expired {
        /// The last valid instant.
        not_after: Timestamp,
    },
}

impl fmt::Display for TimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyWindow => f.write_str("the validity window ends before it starts"),
            Self::SkewTooLarge => f.write_str("the clock-skew tolerance is above 1 hour"),
            Self::NotYetValid { not_before } => write!(f, "not valid before {not_before}"),
            Self::Expired { not_after } => write!(f, "expired at {not_after}"),
        }
    }
}

impl std::error::Error for TimeError {}
