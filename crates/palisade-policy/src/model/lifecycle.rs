//! Rule lifecycle and governance types (#40): instants and dates, what
//! happens when a rule expires, where a rule came from, and the tenant's
//! governance settings.
//!
//! Instants are written as RFC 3339 date-times and dates as RFC 3339 full
//! dates. Both are always UTC inside the engine: an offset is applied when
//! a value is read, and values are written with `Z`. Fractions of a second
//! are dropped, so an instant is a whole number of seconds since
//! 1970-01-01T00:00:00Z.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::settings::unique_keys;

/// Seconds in a day.
pub const DAY_SECS: i64 = 86_400;

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's
/// `days_from_civil`).
const fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date of a day number (H. Hinnant's `civil_from_days`).
const fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

const fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Reads exactly `n` ASCII digits.
fn digits(s: &[u8], n: usize) -> Option<i64> {
    let part = s.get(..n)?;
    part.iter().try_fold(0i64, |acc, b| {
        b.is_ascii_digit().then(|| acc * 10 + i64::from(b - b'0'))
    })
}

/// Parses `YYYY-MM-DD` into a day number. Years 0001 to 9999.
fn parse_date(s: &[u8]) -> Option<i64> {
    if s.len() != 10 || s[4] != b'-' || s[7] != b'-' {
        return None;
    }
    let y = digits(s, 4)?;
    let m = digits(&s[5..], 2)?;
    let d = digits(&s[8..], 2)?;
    if y < 1 || !(1..=12).contains(&m) || d < 1 || d > days_in_month(y, m) {
        return None;
    }
    Some(days_from_civil(y, m, d))
}

/// The first representable instant, 0001-01-01T00:00:00Z.
const MIN_SECS: i64 = -62_135_596_800;
/// The last representable instant, 9999-12-31T23:59:59Z.
const MAX_SECS: i64 = 253_402_300_799;

/// An instant: whole seconds since 1970-01-01T00:00:00Z. Only instants in
/// years 0001 to 9999 (UTC) are read and produced, so every instant has an
/// RFC 3339 form that reads back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(pub i64);

impl Timestamp {
    /// The instant, if it is in years 0001 to 9999 UTC.
    #[must_use]
    pub const fn checked(secs: i64) -> Option<Self> {
        if secs >= MIN_SECS && secs <= MAX_SECS {
            Some(Self(secs))
        } else {
            None
        }
    }

    /// The instant `days` days later, or `None` past the representable
    /// range.
    #[must_use]
    pub const fn plus_days(self, days: i64) -> Option<Self> {
        match days.checked_mul(DAY_SECS) {
            Some(secs) => match self.0.checked_add(secs) {
                Some(t) => Self::checked(t),
                None => None,
            },
            None => None,
        }
    }

    /// The UTC date the instant falls on.
    #[must_use]
    pub const fn date(self) -> Date {
        Date(self.0.div_euclid(DAY_SECS))
    }

    /// Reads an RFC 3339 date-time: `YYYY-MM-DDTHH:MM:SS`, an optional
    /// fraction, and `Z` or an offset `±HH:MM`. `T` and `Z` may be lower
    /// case. Leap seconds (`:60`) are not accepted.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let s = text.as_bytes();
        let day = parse_date(s.get(..10)?)?;
        if !matches!(s.get(10)?, b'T' | b't') || s.get(13)? != &b':' || s.get(16)? != &b':' {
            return None;
        }
        let (h, mi, sec) = (
            digits(&s[11..], 2)?,
            digits(&s[14..], 2)?,
            digits(&s[17..], 2)?,
        );
        if h > 23 || mi > 59 || sec > 59 {
            return None;
        }
        let mut rest = &s[19..];
        if let Some(frac) = rest.strip_prefix(b".") {
            let n = frac.iter().take_while(|b| b.is_ascii_digit()).count();
            if n == 0 {
                return None;
            }
            rest = &frac[n..];
        }
        let offset = match rest {
            [b'Z' | b'z'] => 0,
            [sign @ (b'+' | b'-'), oh1, oh2, b':', om1, om2] => {
                let oh = digits(&[*oh1, *oh2], 2)?;
                let om = digits(&[*om1, *om2], 2)?;
                if oh > 23 || om > 59 {
                    return None;
                }
                let o = oh * 3600 + om * 60;
                if *sign == b'+' { o } else { -o }
            }
            _ => return None,
        };
        // An offset can move the instant out of years 0001 to 9999.
        Self::checked(day * DAY_SECS + h * 3600 + mi * 60 + sec - offset)
    }
}

impl core::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (y, m, d) = civil_from_days(self.0.div_euclid(DAY_SECS));
        let secs = self.0.rem_euclid(DAY_SECS);
        write!(
            f,
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
            secs / 3600,
            secs % 3600 / 60,
            secs % 60
        )
    }
}

impl core::str::FromStr for Timestamp {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or("expected an RFC 3339 date-time such as 2026-11-25T09:30:00Z")
    }
}

impl Serialize for Timestamp {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for Timestamp {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Timestamp".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "An RFC 3339 date-time, such as `2026-11-25T09:30:00Z`. Read as UTC; fractions of a second are dropped.",
            "type": "string",
            "format": "date-time"
        })
    }
}

/// A calendar date in UTC: days since 1970-01-01.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date(pub i64);

impl Date {
    /// The instant the day starts, clamped to the representable range.
    #[must_use]
    pub const fn start(self) -> Timestamp {
        match self.0.checked_mul(DAY_SECS) {
            Some(t) if t < MIN_SECS => Timestamp(MIN_SECS),
            Some(t) if t > MAX_SECS => Timestamp(MAX_SECS),
            Some(t) => Timestamp(t),
            None if self.0 < 0 => Timestamp(MIN_SECS),
            None => Timestamp(MAX_SECS),
        }
    }

    /// Reads an RFC 3339 full date, `YYYY-MM-DD`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        parse_date(text.as_bytes()).map(Self)
    }
}

impl core::fmt::Display for Date {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (y, m, d) = civil_from_days(self.0);
        write!(f, "{y:04}-{m:02}-{d:02}")
    }
}

impl Serialize for Date {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Date {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s)
            .ok_or_else(|| serde::de::Error::custom("expected a date such as 2026-11-25"))
    }
}

impl JsonSchema for Date {
    // Not `Date`: that name is the scope schedules' calendar date (#38),
    // and two definitions with one name would replace each other.
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "UtcDate".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "An RFC 3339 full date, such as `2026-11-25`, in UTC.",
            "type": "string",
            "format": "date"
        })
    }
}

/// What happens when a rule expires.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OnExpire {
    /// The rule behaves as absent. The default.
    #[default]
    Deactivate,
    /// The rule is deleted this many days after it expires (1 to 3650):
    /// it behaves as absent at once, and [`crate::lifecycle::retire_due`]
    /// lists it for deletion once the days have passed.
    DeleteAfterDays(#[schemars(range(min = 1, max = 3650))] u16),
    /// The rule becomes an `audit` rule: it still records matches, but no
    /// longer decides.
    ConvertToAudit,
}

impl OnExpire {
    /// Whether this is the default.
    #[must_use]
    pub fn is_default(&self) -> bool {
        *self == Self::Deactivate
    }
}

/// Where a rule came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuleSource {
    /// Written by an administrator.
    Manual,
    /// From learning mode (#5).
    Learned,
    /// Accepted from a recommendation (#5).
    Recommendation,
    /// From the curated catalogue.
    Catalogue,
    /// Imported from another format.
    Import,
    /// Created through the API (#15).
    Api,
    /// From an approved user request (#11).
    ApprovalRequest,
}

/// The risk an exception carries.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RiskRating {
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// High.
    High,
}

/// How serious a policy-assistant finding is (#40).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    /// Informational.
    Info,
    /// Probably a mistake or a risk.
    Warning,
    /// Blocks publishing unless a tenant administrator overrides it.
    Error,
}

/// Limits on the governance settings, used by the schema and validation.
pub mod limits {
    /// Longest exception, in days (Essential Eight exceptions process).
    pub const MAX_EXCEPTION_DAYS: i64 = 365;
    /// The default review period, in days, from `created_at`.
    pub const REVIEW_PERIOD_DAYS: i64 = 365;
    /// Shortest and longest `stale_after_days`.
    pub const STALE_AFTER_DAYS: core::ops::RangeInclusive<u16> = 1..=3650;
    /// Shortest and longest `expiring_soon_days`.
    pub const EXPIRING_SOON_DAYS: core::ops::RangeInclusive<u16> = 1..=365;
    /// Most expiry notices.
    pub const MAX_EXPIRY_NOTICES: usize = 8;
    /// Latest expiry notice, in days before expiry.
    pub const MAX_EXPIRY_NOTICE_DAYS: u16 = 365;
    /// Shortest and longest counter report interval, in hours.
    pub const COUNTER_REPORT_HOURS: core::ops::RangeInclusive<u16> = 1..=168;
}

/// The tenant's governance settings (#40). Every field is optional.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct GovernanceSettings {
    /// Governance mode: allow, trust, exclusion and exception rules need a
    /// justification, allow and trust rules a review date, and exception
    /// rules an expiry, an approver and a risk rating. Unset means on for
    /// a policy with a compliance preset (`unknown.preset`) and off
    /// otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_justification: Option<bool>,
    /// A rule with no hits for this many days, while usage was observed,
    /// is stale: 1 to 3650, default 90.
    #[schemars(range(min = 1, max = 3650))]
    pub stale_after_days: u16,
    /// A rule that expires within this many days is expiring soon: 1 to
    /// 365, default 14.
    #[schemars(range(min = 1, max = 365))]
    pub expiring_soon_days: u16,
    /// When the server tells a rule's owner that it expires, in days
    /// before the expiry: at most 8 values, each at most 365, default
    /// `[14, 3, 0]`.
    #[schemars(length(max = 8), inner(range(max = 365)))]
    pub expiry_notice_days: Vec<u16>,
    /// How often the agent reports hit counters, in hours: 1 to 168,
    /// default 24.
    #[schemars(range(min = 1, max = 168))]
    pub counter_report_hours: u16,
    /// The severity of policy-assistant findings, per finding code,
    /// replacing the default.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(deserialize_with = "unique_keys")]
    #[schemars(transform = finding_code_keys)]
    pub severity: BTreeMap<String, FindingSeverity>,
}

impl Default for GovernanceSettings {
    fn default() -> Self {
        Self {
            require_justification: None,
            stale_after_days: 90,
            expiring_soon_days: 14,
            expiry_notice_days: vec![14, 3, 0],
            counter_report_hours: 24,
            severity: BTreeMap::new(),
        }
    }
}

impl GovernanceSettings {
    /// Whether every setting has its default.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    /// Whether governance mode is on: `require_justification`, or, when
    /// it is unset, whether the policy has a compliance preset (`preset`).
    #[must_use]
    pub fn mode(&self, preset: bool) -> bool {
        self.require_justification.unwrap_or(preset)
    }

    /// The same settings with governance mode written out when the policy
    /// gets it from its compliance preset (`preset`), so that merging
    /// layers ([`stricter`](Self::stricter)) keeps a mode an outer layer
    /// gets from its preset. A mode that is off is left as written, so a
    /// hierarchy where no layer is governed merges to the same settings as
    /// before.
    #[must_use]
    pub fn resolved(&self, preset: bool) -> Self {
        Self {
            require_justification: if self.mode(preset) {
                Some(true)
            } else {
                self.require_justification
            },
            ..self.clone()
        }
    }

    /// The stricter combination of `self`, the nearer layer, and `other`,
    /// for building an effective policy (#37). Resolve each layer first
    /// ([`resolved`](Self::resolved)): governance mode is then on if
    /// either side has it on, by setting or by preset. Rules go stale and
    /// expiry warnings start at the earlier point; counters report at the
    /// shorter interval; the nearest expiry notices of either side are
    /// sent, at most 8; and each finding's severity is the more serious
    /// one, a side without an entry counting as the code's default. A
    /// nearer layer can therefore not relax governance that an outer layer
    /// requires.
    #[must_use]
    pub fn stricter(&self, other: &Self) -> Self {
        let require_justification = match (self.require_justification, other.require_justification)
        {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (Some(false), _) | (_, Some(false)) => Some(false),
            (None, None) => None,
        };
        // The notices closest to expiry are kept: the last warning before a
        // rule stops deciding matters most.
        let mut notices: Vec<u16> = self
            .expiry_notice_days
            .iter()
            .chain(&other.expiry_notice_days)
            .copied()
            .collect();
        notices.sort_unstable();
        notices.dedup();
        notices.truncate(limits::MAX_EXPIRY_NOTICES);
        notices.reverse();
        let mut severity = BTreeMap::new();
        for key in self.severity.keys().chain(other.severity.keys()) {
            let default = crate::analysis::FindingCode::from_name(key).map_or(
                FindingSeverity::Info,
                crate::analysis::FindingCode::default_severity,
            );
            let of = |m: &BTreeMap<String, FindingSeverity>| m.get(key).copied().unwrap_or(default);
            severity.insert(key.clone(), of(&self.severity).max(of(&other.severity)));
        }
        Self {
            require_justification,
            stale_after_days: self.stale_after_days.min(other.stale_after_days),
            expiring_soon_days: self.expiring_soon_days.max(other.expiring_soon_days),
            expiry_notice_days: notices,
            counter_report_hours: self.counter_report_hours.min(other.counter_report_hours),
            severity,
        }
    }
}

/// The schema of `severity` keys: the finding codes.
fn finding_code_keys(schema: &mut schemars::Schema) {
    let names: Vec<&str> = crate::analysis::FindingCode::ALL
        .iter()
        .map(|c| c.as_str())
        .collect();
    schema.insert(
        "propertyNames".to_owned(),
        serde_json::json!({ "enum": names }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_read_rfc3339_and_write_utc() {
        for (text, secs) in [
            ("1970-01-01T00:00:00Z", 0),
            ("1970-01-01T00:00:00.999Z", 0),
            ("2026-11-25T09:30:00Z", 1_795_599_000),
            ("2026-11-25t19:30:00+10:00", 1_795_599_000),
            ("2026-11-24T23:00:00-10:30", 1_795_599_000),
            ("2000-02-29T00:00:00Z", 951_782_400),
            ("1969-12-31T23:59:59Z", -1),
        ] {
            assert_eq!(Timestamp::parse(text), Some(Timestamp(secs)), "{text}");
        }
        assert_eq!(Timestamp(1_795_599_000).to_string(), "2026-11-25T09:30:00Z");
        assert_eq!(Timestamp(-1).to_string(), "1969-12-31T23:59:59Z");
        for bad in [
            "2026-11-25",
            "2026-11-25T09:30:00",
            "2026-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-11-25T24:00:00Z",
            "2026-11-25T23:59:60Z",
            "2026-11-25T09:30:00.Z",
            "2026-11-25T09:30:00+1000",
            "2026-11-25 09:30:00Z",
            "0000-01-01T00:00:00Z",
            "2026-11-25T09:30:00Z ",
            "0001-01-01T00:00:00+01:00",
            "9999-12-31T23:30:00-01:00",
        ] {
            assert_eq!(Timestamp::parse(bad), None, "{bad}");
        }
    }

    /// F5: a side with no entry for a code counts as the code's default,
    /// so merging with a layer that never mentions it cannot lower it.
    /// Notices: the eight nearest to expiry are kept.
    #[test]
    fn merging_keeps_default_severities_and_the_nearest_notices() {
        let outer = GovernanceSettings::default();
        let mut nearer = GovernanceSettings::default();
        // As a merged policy could hold before validation rejected it.
        nearer
            .severity
            .insert("missing_justification".into(), FindingSeverity::Info);
        let merged = nearer.stricter(&outer);
        assert_eq!(
            merged.severity.get("missing_justification"),
            Some(&FindingSeverity::Error)
        );
        let merged = outer.stricter(&nearer);
        assert_eq!(
            merged.severity.get("missing_justification"),
            Some(&FindingSeverity::Error)
        );
        let a = GovernanceSettings {
            expiry_notice_days: vec![60, 30, 20, 14, 10],
            ..GovernanceSettings::default()
        };
        let b = GovernanceSettings {
            expiry_notice_days: vec![90, 7, 5, 3, 1, 0],
            ..GovernanceSettings::default()
        };
        // Before the fix the farthest were kept: 90, 60, 30, 20, 14, 10, 7,
        // 5, dropping the notices at 3, 1 and 0 days.
        assert_eq!(
            a.stricter(&b).expiry_notice_days,
            vec![20, 14, 10, 7, 5, 3, 1, 0]
        );
        // Resolving keeps an explicit `false` without a preset.
        let off = GovernanceSettings {
            require_justification: Some(false),
            ..GovernanceSettings::default()
        };
        assert_eq!(off.resolved(false).require_justification, Some(false));
        assert_eq!(off.resolved(true).require_justification, Some(false));
        assert_eq!(
            GovernanceSettings::default()
                .resolved(true)
                .require_justification,
            Some(true)
        );
    }

    #[test]
    fn dates_round_trip() {
        for text in [
            "1970-01-01",
            "2000-02-29",
            "2026-11-25",
            "9999-12-31",
            "0001-01-01",
        ] {
            assert_eq!(Date::parse(text).unwrap().to_string(), text);
        }
        assert_eq!(
            Date::parse("2026-11-25").unwrap().start(),
            Timestamp(1_795_564_800)
        );
        assert_eq!(
            Timestamp(1_795_599_000).date(),
            Date::parse("2026-11-25").unwrap()
        );
        assert_eq!(Date::parse("2025-02-29"), None);
        assert_eq!(Date(i64::MIN).start(), Timestamp(MIN_SECS));
        assert_eq!(Date(i64::MAX).start(), Timestamp(MAX_SECS));
        assert_eq!(Timestamp(MAX_SECS).plus_days(1), None);
        assert_eq!(Date::parse("2026-1-01"), None);
    }

    #[test]
    fn on_expire_has_string_and_map_forms() {
        assert_eq!(
            serde_json::to_value(OnExpire::Deactivate).unwrap(),
            "deactivate"
        );
        assert_eq!(
            serde_json::to_value(OnExpire::DeleteAfterDays(30)).unwrap(),
            serde_json::json!({"delete_after_days": 30})
        );
        let v: OnExpire = serde_json::from_value(serde_json::json!("convert_to_audit")).unwrap();
        assert_eq!(v, OnExpire::ConvertToAudit);
    }

    proptest::proptest! {
        #[test]
        fn every_instant_round_trips(secs in -62_135_596_800i64..253_402_300_799) {
            let t = Timestamp(secs);
            proptest::prop_assert_eq!(Timestamp::parse(&t.to_string()), Some(t));
        }
    }
}
