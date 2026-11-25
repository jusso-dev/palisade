//! Schedules: when a scope is active (#38).
//!
//! A [`CompiledSchedule`] is evaluated at an instant (seconds since the
//! Unix epoch, from the agent's trusted time) in one time zone, chosen by
//! the schedule's `timezone_basis`:
//!
//! - `utc`: Coordinated Universal Time.
//! - `device_local`: the device's zone ([`ScopeFacts::device_time_zone`]).
//! - `user_local`: the session user's zone
//!   ([`ScopeFacts::session_time_zone`]) if the agent could read it, and
//!   otherwise the device's, with the note `timezone_fallback`.
//!
//! Zones are IANA names, resolved with the time zone database bundled
//! into the binary, so evaluation never reads the system.
//!
//! # Windows
//!
//! A window on day `D` from `start` to `end` is active from the instant
//! that is `start` on `D` to the instant that is `end` on `D` (or on the
//! next day, if `end` is not after `start`), including the first and
//! excluding the second. `24:00` is midnight at the end of the day. A
//! window with `duration_mins` lasts that many minutes of elapsed time from
//! its start, whatever the clocks do.
//!
//! Local times are turned into instants with the "compatible" rule of the
//! ECMAScript Temporal proposal: a time that occurs twice, when clocks go
//! back, is its first occurrence; a time that is skipped, when clocks go
//! forward, is moved forward by the length of the gap (02:30 on a day that
//! jumps from 02:00 to 03:00 is 03:30). So a window `01:00`–`03:00` on the
//! day clocks go back lasts three hours of elapsed time, and on the day
//! they go forward one hour.
//!
//! # Dates
//!
//! `dates` and `except_dates` test the local date of the instant being
//! decided, not the day a window started on. With `dates`, the schedule is
//! only active on those dates; on an `except_dates` date it is never
//! active.

use jiff::Timestamp;
use jiff::civil::{Date, DateTime, Time};
use jiff::tz::TimeZone;

use crate::model::TimeZoneBasis;
use crate::ops::Tri;

use super::compile::Bias;
use super::facts::ScopeFacts;
use super::model::{DEFAULT_GRACE_SECS, OnWindowClose, Schedule, Weekday};
use super::{ScopeNote, ScopeNotes};

/// A schedule ready to evaluate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledSchedule {
    /// Some part of the schedule was not well formed. Such a schedule is
    /// never trusted to say when it is active: it reads as an untrusted
    /// clock does.
    invalid: bool,
    basis: TimeZoneBasis,
    windows: Vec<CWindow>,
    dates: Vec<(Date, Date)>,
    except: Vec<(Date, Date)>,
    on_close: OnWindowClose,
    grace_secs: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CWindow {
    /// Bit `n` is set for weekday `n`, from Monday.
    days: u8,
    /// Minutes after midnight.
    start: u16,
    end: End,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// A wall-clock time, minutes after midnight, on the start day or the
    /// next day.
    At { minutes: u16, next_day: bool },
    /// Elapsed minutes after the start.
    After(u32),
}

const fn day_bit(day: Weekday) -> u8 {
    1 << (day as u8)
}

impl CompiledSchedule {
    /// Compiles a schedule. `default_basis` is the policy's
    /// `settings.time_zone_basis`, used when the schedule sets none.
    ///
    /// Validation rejects a schedule that is not well formed, but a
    /// library schedule (#37) arrives unvalidated. If a window is not well
    /// formed ([`Window::minutes`](super::Window::minutes) is `None`), a
    /// date range ends before it starts, or a list is over its limit, the
    /// schedule is compiled as invalid: it then evaluates as a schedule
    /// read without trusted time does, keeping permitting rules inactive
    /// and restricting rules active (`fact_malformed`).
    #[must_use]
    pub fn compile(schedule: &Schedule, default_basis: TimeZoneBasis) -> Self {
        use super::limits::{MAX_DATE_RANGES, MAX_GRACE_SECS, MAX_WINDOWS};
        let invalid = schedule.windows.len() > MAX_WINDOWS
            || schedule.dates.len() > MAX_DATE_RANGES
            || schedule.except_dates.len() > MAX_DATE_RANGES
            || schedule.windows.iter().any(|w| w.minutes().is_none())
            || !schedule.dates.iter().all(super::DateRange::is_ordered)
            || !schedule
                .except_dates
                .iter()
                .all(super::DateRange::is_ordered)
            || schedule.grace_secs.is_some_and(|g| g > MAX_GRACE_SECS);
        let windows = schedule
            .windows
            .iter()
            .filter(|w| w.minutes().is_some())
            .map(|w| CWindow {
                days: w.days.iter().fold(0, |acc, d| acc | day_bit(*d)),
                start: w.start.minutes(),
                end: match (w.end, w.duration_mins) {
                    (Some(end), _) => End::At {
                        minutes: end.minutes(),
                        next_day: end.minutes() <= w.start.minutes(),
                    },
                    (None, Some(d)) => End::After(d),
                    (None, None) => End::After(0),
                },
            })
            .collect();
        let range = |r: &super::DateRange| (r.from.0, r.last().0);
        Self {
            invalid,
            basis: schedule.timezone_basis.unwrap_or(default_basis),
            windows,
            dates: schedule.dates.iter().map(range).collect(),
            except: schedule.except_dates.iter().map(range).collect(),
            on_close: schedule.on_window_close,
            grace_secs: schedule.grace_secs.unwrap_or(DEFAULT_GRACE_SECS),
        }
    }

    /// Whether every part of the schedule was well formed.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        !self.invalid
    }

    /// What happens to running processes when the schedule closes.
    #[must_use]
    pub const fn on_window_close(&self) -> OnWindowClose {
        self.on_close
    }

    /// The grace period, in seconds.
    #[must_use]
    pub const fn grace_secs(&self) -> u32 {
        self.grace_secs
    }

    /// The time zone the schedule is read in, from the facts. `Err` with
    /// the notes if it is unknown.
    pub fn zone(&self, facts: &ScopeFacts) -> Result<(TimeZone, ScopeNotes), ScopeNotes> {
        let mut notes = ScopeNotes::default();
        let name = match self.basis {
            TimeZoneBasis::Utc => return Ok((TimeZone::UTC, notes)),
            TimeZoneBasis::DeviceLocal => facts.device_time_zone.as_deref(),
            TimeZoneBasis::UserLocal => match facts.session_time_zone.as_deref() {
                Some(zone) => Some(zone),
                None => {
                    notes.insert(ScopeNote::TimezoneFallback);
                    facts.device_time_zone.as_deref()
                }
            },
        };
        match name.map(TimeZone::get) {
            Some(Ok(tz)) => Ok((tz, notes)),
            Some(Err(_)) => {
                notes.insert(ScopeNote::FactMalformed);
                Err(notes)
            }
            None => {
                notes.insert(ScopeNote::FactMissing);
                Err(notes)
            }
        }
    }

    /// Evaluates the schedule for one rule. `positive` is whether the
    /// schedule being active makes the rule apply (it is not under
    /// `negate`). Without trusted time or a known zone, the schedule reads
    /// as whatever keeps a permitting rule inactive and a restricting rule
    /// active, with `clock_untrusted`.
    pub(crate) fn eval(&self, facts: &ScopeFacts, positive: bool, bias: Bias) -> (Tri, ScopeNotes) {
        let restrictive = |mut notes: ScopeNotes| {
            notes.insert(ScopeNote::ClockUntrusted);
            (bias.favours(positive), notes)
        };
        if self.invalid {
            let mut notes = ScopeNotes::default();
            notes.insert(ScopeNote::FactMalformed);
            return (bias.favours(positive), notes);
        }
        let Some(time) = facts.time.filter(|t| t.trusted) else {
            let mut notes = ScopeNotes::default();
            if facts.time.is_none() {
                notes.insert(ScopeNote::FactMissing);
            }
            return restrictive(notes);
        };
        match self.zone(facts) {
            Ok((tz, notes)) => match self.is_active(time.unix_secs, &tz) {
                Some(active) => (Tri::from_bool(active), notes),
                None => {
                    let mut notes = notes;
                    notes.insert(ScopeNote::FactMalformed);
                    restrictive(notes)
                }
            },
            Err(notes) => restrictive(notes),
        }
    }

    /// Whether the schedule is active at `unix_secs` in `tz`. `None` if the
    /// schedule is invalid, or the instant is outside the years -9999 to
    /// 9999.
    #[must_use]
    pub fn is_active(&self, unix_secs: i64, tz: &TimeZone) -> Option<bool> {
        if self.invalid {
            return None;
        }
        let date = local(unix_secs, tz)?.date();
        if !self.date_ok(date) {
            return Some(false);
        }
        if self.windows.is_empty() {
            return Some(true);
        }
        Some(self.window_end(unix_secs, tz, date).is_some())
    }

    /// The instant the schedule next stops being active, after
    /// `unix_secs`, if it is active then and stops within 64 window or
    /// date boundaries. The agent re-evaluates on every heartbeat, so a
    /// later close is still acted on.
    #[must_use]
    pub fn closes_at(&self, unix_secs: i64, tz: &TimeZone) -> Option<i64> {
        if self.is_active(unix_secs, tz) != Some(true) {
            return None;
        }
        let mut cur = unix_secs;
        for _ in 0..64 {
            let date = local(cur, tz)?.date();
            let window = if self.windows.is_empty() {
                None
            } else {
                self.window_end(cur, tz, date)
            };
            let day = self
                .date_boundary(date)
                .and_then(|d| resolve(d.to_datetime(Time::midnight()), tz));
            let next = match (window, day) {
                (Some(a), Some(b)) => a.min(b),
                (a, b) => a.or(b)?,
            };
            if next <= cur {
                return None;
            }
            cur = next;
            if self.is_active(cur, tz)? {
                continue;
            }
            return Some(cur);
        }
        None
    }

    /// Whether `date` passes `dates` and `except_dates`.
    fn date_ok(&self, date: Date) -> bool {
        let within = |r: &(Date, Date)| r.0 <= date && date <= r.1;
        (self.dates.is_empty() || self.dates.iter().any(within)) && !self.except.iter().any(within)
    }

    /// The first date after `date` on which the date test may change, if
    /// there is one.
    fn date_boundary(&self, date: Date) -> Option<Date> {
        self.dates
            .iter()
            .chain(&self.except)
            .filter_map(|&(from, last)| {
                if from > date {
                    Some(from)
                } else if last >= date {
                    last.tomorrow().ok()
                } else {
                    None
                }
            })
            .min()
    }

    /// The latest end of the windows that contain `t`, whose local date is
    /// `date`, or `None` if none does.
    fn window_end(&self, t: i64, tz: &TimeZone, date: Date) -> Option<i64> {
        let mut best: Option<i64> = None;
        for w in &self.windows {
            // A window starts at most 7 days and a few hours of clock
            // changes before `t`. A start on the next local date can still
            // be before `t` when clocks go back over midnight.
            for back in -1i64..=8 {
                let day = if back < 0 {
                    date.tomorrow()
                } else {
                    date.checked_sub(jiff::Span::new().days(back))
                };
                let Ok(day) = day else { continue };
                if w.days & day_bit(Weekday::of(day)) == 0 {
                    continue;
                }
                let Some((start, end)) = w.span(day, tz) else {
                    continue;
                };
                if start <= t && t < end {
                    best = Some(best.map_or(end, |b| b.max(end)));
                }
            }
        }
        best
    }
}

impl CWindow {
    /// The instants the window starting on `day` begins and ends.
    fn span(self, day: Date, tz: &TimeZone) -> Option<(i64, i64)> {
        let start = at(day, self.start, tz)?;
        let end = match self.end {
            End::At { minutes, next_day } => {
                let end_day = if next_day { day.tomorrow().ok()? } else { day };
                at(end_day, minutes, tz)?
            }
            End::After(mins) => start.checked_add(i64::from(mins) * 60)?,
        };
        Some((start, end))
    }
}

/// The local date and time of an instant.
fn local(unix_secs: i64, tz: &TimeZone) -> Option<DateTime> {
    Some(tz.to_datetime(Timestamp::from_second(unix_secs).ok()?))
}

/// The instant that is `minutes` after midnight on `day` (1440 is the next
/// midnight), by the compatible rule.
fn at(day: Date, minutes: u16, tz: &TimeZone) -> Option<i64> {
    let (day, minutes) = if minutes >= 1440 {
        (day.tomorrow().ok()?, minutes - 1440)
    } else {
        (day, minutes)
    };
    let h = i8::try_from(minutes / 60).ok()?;
    let m = i8::try_from(minutes % 60).ok()?;
    resolve(day.to_datetime(Time::new(h, m, 0, 0).ok()?), tz)
}

/// The instant of a local time by the compatible rule of the Temporal
/// proposal, which jiff implements: the earlier of two, and for a skipped
/// time, the local time read with the offset in force before the gap.
fn resolve(local: DateTime, tz: &TimeZone) -> Option<i64> {
    tz.to_ambiguous_timestamp(local)
        .compatible()
        .ok()
        .map(Timestamp::as_second)
}

impl Bias {
    /// The value that makes a rule of this bias apply in a position of
    /// this polarity: more for a restricting rule, less for a permitting
    /// one.
    pub(crate) const fn favours(self, positive: bool) -> Tri {
        Tri::from_bool(matches!(self, Self::Restrictive) == positive)
    }
}

#[cfg(test)]
mod tests;
