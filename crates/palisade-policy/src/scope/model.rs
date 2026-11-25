//! The serialised form of scopes (#38): what a policy document holds.

use core::fmt;

use jiff::civil;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::context::SessionType;
use crate::model::{RuleSetId, TimeZoneBasis};
use palisade_core::Uuid7;

/// Limits on scopes, enforced by validation.
pub mod limits {
    /// Most entries in one `include` or `exclude` list, and in one client
    /// filter list. Larger lists belong in a library set (#37).
    pub const MAX_SCOPE_ENTRIES: usize = 1000;
    /// Most windows in one schedule.
    pub const MAX_WINDOWS: usize = 64;
    /// Most date ranges in `dates` or `except_dates`.
    pub const MAX_DATE_RANGES: usize = 1000;
    /// Longest window, in minutes (seven days).
    pub const MAX_WINDOW_MINUTES: u32 = 7 * 1440;
    /// Longest grace period after a window closes, in seconds (one day).
    pub const MAX_GRACE_SECS: u32 = 86_400;
    /// Most scopes on one rule-set assignment.
    pub const MAX_ASSIGNMENT_SCOPES: usize = 8;
    /// Most scopes on one rule-set assignment of an effective policy (#37):
    /// an authored assignment's, plus the contributing policy's own scope,
    /// which moves onto its rule sets.
    pub const MAX_EFFECTIVE_ASSIGNMENT_SCOPES: usize = MAX_ASSIGNMENT_SCOPES + 1;
    /// Most network location profiles in a policy.
    pub const MAX_LOCATION_PROFILES: usize = 64;
    /// Most criteria in one location profile.
    pub const MAX_PROFILE_REFS: usize = 32;
    /// Longest pattern, name or other scope value, in UTF-8 bytes.
    pub const MAX_SCOPE_VALUE_BYTES: usize = 512;
}

/// Who, where and when a rule applies (#38).
///
/// Every field is optional. An empty scope applies to everyone, everywhere,
/// always. A scope only ever narrows: a rule applies when its match tree
/// matches **and** every scope on the way to it matches (the policy's, its
/// rule set assignment's, and its own).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    /// Users and groups.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principals: Option<RefList<PrincipalRef>>,
    /// Devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devices: Option<RefList<DeviceRef>>,
    /// The device's network location.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<RefList<NetworkRef>>,
    /// The session type and, on a multi-session host, the connecting client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<SessionFilter>,
    /// When the scope is active, written in place. At most one of
    /// `schedule` and `schedule_set`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<Schedule>,
    /// When the scope is active, as a schedule from the library (#37).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule_set: Option<SetRef>,
    /// How the dimensions that are set combine: `all` (the default) needs
    /// every one to match, `any` needs one.
    #[serde(default, skip_serializing_if = "Combine::is_all")]
    pub combine: Combine,
    /// Apply when the scope does **not** match.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub negate: bool,
    /// Whose token `principals` is tested against.
    #[serde(default, skip_serializing_if = "ScopeSubject::is_process_user")]
    pub subject: ScopeSubject,
    /// Only on the scope of a rule that lets an object run: at most this
    /// many instances per session. `0`, the default, means no limit.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub max_instances_per_session: u32,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde passes a reference
const fn is_zero(n: &u32) -> bool {
    *n == 0
}

impl Scope {
    /// Whether no field is set: the scope applies to everything.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// Whether any dimension is set.
    #[must_use]
    pub const fn has_dimension(&self) -> bool {
        self.principals.is_some()
            || self.devices.is_some()
            || self.network.is_some()
            || self.sessions.is_some()
            || self.schedule.is_some()
            || self.schedule_set.is_some()
    }
}

/// An `include` and an `exclude` list. An empty `include` means every
/// entry; a match in `exclude` always wins.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, bound(deserialize = "T: Deserialize<'de>"))]
pub struct RefList<T> {
    /// Matches when any entry matches. Empty means everyone or everything.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 1000))]
    pub include: Vec<T>,
    /// Never matches when any entry matches, whatever `include` says.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 1000))]
    pub exclude: Vec<T>,
}

impl<T> Default for RefList<T> {
    fn default() -> Self {
        Self {
            include: Vec::new(),
            exclude: Vec::new(),
        }
    }
}

/// How a scope's dimensions combine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Combine {
    /// Every dimension that is set must match. The default.
    #[default]
    All,
    /// At least one dimension that is set must match.
    Any,
}

impl Combine {
    #[allow(clippy::trivially_copy_pass_by_ref)] // serde passes a reference
    const fn is_all(&self) -> bool {
        matches!(self, Self::All)
    }
}

/// Whose token a scope's `principals` is tested against.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScopeSubject {
    /// The user the process runs as. The default.
    #[default]
    ProcessUser,
    /// The user logged on to the process's session, for example to scope a
    /// service running as SYSTEM on behalf of the interactive user.
    SessionUser,
    /// The user the parent process runs as.
    ParentProcessUser,
}

impl ScopeSubject {
    #[allow(clippy::trivially_copy_pass_by_ref)] // serde passes a reference
    const fn is_process_user(&self) -> bool {
        matches!(self, Self::ProcessUser)
    }
}

/// A reference to a library set (#37): its ID and an optional version pin,
/// the same reference match trees and hierarchy assignments use.
pub type SetRef = crate::library::LibraryRef;

pub use crate::library::Pin;

/// A user or group (#38). Each is an object with one key, the kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PrincipalRef {
    /// A user or group SID, such as `S-1-5-32-544`.
    Sid(String),
    /// A well-known account or group.
    WellKnown(WellKnown),
    /// A local group, by name, resolved on the device. Case-insensitive.
    LocalGroup(String),
    /// A directory group, by SID. The name is for display only.
    DirectoryGroup(DirectoryGroup),
    /// A cloud-directory group, by tenant and object ID.
    CloudGroup(CloudObject),
    /// A wildcard on the `DOMAIN\user` account name, such as `*\svc_*`.
    /// Names can be spoofed, so a pattern may only narrow a rule that lets
    /// an object run, and only widen a deny (validation).
    UserPattern(String),
    /// A principal set from the library (#37): SIDs and object IDs.
    PrincipalSet(SetRef),
}

/// A well-known account or group, with a fixed SID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WellKnown {
    /// `S-1-1-0`.
    Everyone,
    /// `S-1-5-11`.
    AuthenticatedUsers,
    /// The local Administrators group, `S-1-5-32-544`.
    Administrators,
    /// The local Users group, `S-1-5-32-545`.
    Users,
    /// The local system account, `S-1-5-18`.
    System,
    /// `S-1-5-19`.
    LocalService,
    /// `S-1-5-20`.
    NetworkService,
    /// Interactive logons, `S-1-5-4`.
    Interactive,
    /// `S-1-5-32-555`.
    RemoteDesktopUsers,
    /// Any domain's Domain Controllers group (relative ID 516), or the
    /// Enterprise Domain Controllers group, `S-1-5-9`.
    DomainControllers,
}

impl WellKnown {
    /// Every well-known principal.
    pub const ALL: [Self; 10] = [
        Self::Everyone,
        Self::AuthenticatedUsers,
        Self::Administrators,
        Self::Users,
        Self::System,
        Self::LocalService,
        Self::NetworkService,
        Self::Interactive,
        Self::RemoteDesktopUsers,
        Self::DomainControllers,
    ];

    /// The fixed SID, in canonical form. `DomainControllers` gives the
    /// enterprise group; the domain-relative ones are matched by RID.
    #[must_use]
    pub const fn sid(self) -> &'static str {
        match self {
            Self::Everyone => "S-1-1-0",
            Self::AuthenticatedUsers => "S-1-5-11",
            Self::Administrators => "S-1-5-32-544",
            Self::Users => "S-1-5-32-545",
            Self::System => "S-1-5-18",
            Self::LocalService => "S-1-5-19",
            Self::NetworkService => "S-1-5-20",
            Self::Interactive => "S-1-5-4",
            Self::RemoteDesktopUsers => "S-1-5-32-555",
            Self::DomainControllers => "S-1-5-9",
        }
    }
}

/// A directory group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectoryGroup {
    /// The group's SID.
    pub sid: String,
    /// The display name, for people. Never matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 128))]
    pub name: Option<String>,
}

/// An object in a cloud directory: a group of users or of devices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CloudObject {
    /// The tenant's ID, a GUID.
    pub tenant_id: String,
    /// The object's ID, a GUID.
    pub object_id: String,
}

/// A device or group of devices (#38).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DeviceRef {
    /// The device's Palisade ID.
    DeviceId(Uuid7),
    /// A wildcard on the host name or the fully qualified domain name,
    /// such as `FIN-*`. Case-insensitive.
    HostnamePattern(String),
    /// A device set from the library (#37), static or dynamic. The server
    /// works out which sets a device is in.
    DeviceSet(SetRef),
    /// A directory computer group, by SID.
    DirectoryComputerGroup(String),
    /// A cloud-directory device group.
    CloudDeviceGroup(CloudObject),
    /// A directory organisational unit.
    Ou(OuRef),
    /// A device tag, such as `site=sydney`. Case-insensitive.
    Tag(String),
}

/// A directory organisational unit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OuRef {
    /// The OU's distinguished name, such as `OU=Finance,DC=corp,DC=example`.
    pub dn: String,
    /// Also match devices in OUs below it.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub include_sub_ous: bool,
}

/// A network location test (#38). Address tests match when any local
/// interface address does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NetworkRef {
    /// An address block, such as `10.20.0.0/16` or `2001:db8::/32`.
    Cidr(String),
    /// An inclusive address range, such as `10.0.0.10-10.0.0.99`.
    Range(String),
    /// A connection-specific DNS suffix, such as `corp.example.org`. Also
    /// matches suffixes below it. Case-insensitive.
    DnsSuffix(String),
    /// A default gateway's hardware address, such as `00-1a-2b-3c-4d-5e`.
    GatewayMac(String),
    /// Whether the management server is reachable.
    ServerReachable(bool),
    /// A named location profile of the policy (`location_profiles`).
    LocationProfile(String),
    /// A network set from the library (#37): address blocks, ranges and DNS
    /// suffixes.
    NetworkSet(SetRef),
}

/// Session criteria (#38).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionFilter {
    /// The session types. Empty means every type.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<SessionType>,
    /// The connecting client, on a multi-session host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientFilter>,
}

/// The client connected to a remote desktop session, for per-client
/// scoping on multi-session hosts. Each list that is set must match.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientFilter {
    /// Wildcards on the client's host name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 1000))]
    pub hostname: Vec<String>,
    /// Address blocks (`10.0.0.0/8`) or ranges (`10.0.0.1-10.0.0.9`) for
    /// the client's address.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 1000))]
    pub ip: Vec<String>,
    /// Device sets (#37) the client device is in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 1000))]
    pub device_sets: Vec<SetRef>,
}

/// When a scope is active (#38).
///
/// Times are wall-clock times in the schedule's time zone. A window starts
/// on one of its days at `start` and lasts until `end` (which may be on
/// the next day: `22:00` to `06:00` wraps midnight) or for `duration_mins`.
/// With no windows, every time of day is in. `dates` and `except_dates`
/// test the local date of the moment being decided.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    /// The clock the times are read on. Unset means the policy's
    /// `settings.time_zone_basis`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone_basis: Option<TimeZoneBasis>,
    /// The weekly windows. Empty means all day, every day.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 64))]
    pub windows: Vec<Window>,
    /// Absolute date ranges. Empty means every date.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 1000))]
    pub dates: Vec<DateRange>,
    /// Dates on which the schedule is never active, such as holidays.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 1000))]
    pub except_dates: Vec<DateRange>,
    /// Only for rules that let an object run: what happens to running
    /// processes when the schedule closes.
    #[serde(default, skip_serializing_if = "OnWindowClose::is_none")]
    pub on_window_close: OnWindowClose,
    /// Seconds between the warning and termination, for
    /// `warn_then_terminate`. Default 300.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(max = 86_400))]
    pub grace_secs: Option<u32>,
}

/// The default grace period, in seconds.
pub const DEFAULT_GRACE_SECS: u32 = 300;

/// One weekly window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Window {
    /// The days the window starts on. At least one, each once.
    #[schemars(length(min = 1, max = 7))]
    pub days: Vec<Weekday>,
    /// When the window starts, `HH:MM`.
    pub start: TimeOfDay,
    /// When it ends, `HH:MM`. At or before `start` means the next day.
    /// Exactly one of `end` and `duration_mins`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<TimeOfDay>,
    /// How long it lasts, in minutes, from 1 to 10080.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1, max = 10_080))]
    pub duration_mins: Option<u32>,
}

impl Window {
    /// The window's length in minutes, if it is well formed: at least one
    /// day, each once, a start before `24:00`, exactly one of `end` and
    /// `duration_mins`, and from 1 minute to 7 days.
    #[must_use]
    pub fn minutes(&self) -> Option<u32> {
        let mut seen = 0u8;
        for d in &self.days {
            let bit = 1 << (*d as u8);
            if seen & bit != 0 {
                return None;
            }
            seen |= bit;
        }
        if seen == 0 || self.start.0 >= 1440 {
            return None;
        }
        let minutes = match (self.end, self.duration_mins) {
            (Some(end), None) => {
                let (s, e) = (u32::from(self.start.0), u32::from(end.0));
                if e > s { e - s } else { 1440 - s + e }
            }
            (None, Some(d)) => d,
            _ => return None,
        };
        (1..=limits::MAX_WINDOW_MINUTES)
            .contains(&minutes)
            .then_some(minutes)
    }
}

/// A day of the week.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Weekday {
    /// Monday.
    Mon,
    /// Tuesday.
    Tue,
    /// Wednesday.
    Wed,
    /// Thursday.
    Thu,
    /// Friday.
    Fri,
    /// Saturday.
    Sat,
    /// Sunday.
    Sun,
}

impl Weekday {
    /// The weekday of a date.
    #[must_use]
    pub fn of(date: civil::Date) -> Self {
        match date.weekday() {
            jiff::civil::Weekday::Monday => Self::Mon,
            jiff::civil::Weekday::Tuesday => Self::Tue,
            jiff::civil::Weekday::Wednesday => Self::Wed,
            jiff::civil::Weekday::Thursday => Self::Thu,
            jiff::civil::Weekday::Friday => Self::Fri,
            jiff::civil::Weekday::Saturday => Self::Sat,
            jiff::civil::Weekday::Sunday => Self::Sun,
        }
    }
}

/// A wall-clock time, `HH:MM` from `00:00` to `23:59`, held as minutes
/// since midnight. `24:00` is also accepted, as the end of a day.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimeOfDay(u16);

impl TimeOfDay {
    /// The time `minutes` after midnight, up to 1440 (`24:00`).
    #[must_use]
    pub const fn from_minutes(minutes: u16) -> Option<Self> {
        if minutes <= 1440 {
            Some(Self(minutes))
        } else {
            None
        }
    }

    /// Minutes since midnight.
    #[must_use]
    pub const fn minutes(self) -> u16 {
        self.0
    }
}

impl core::str::FromStr for TimeOfDay {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        const ERR: &str = "expected a time `HH:MM` from 00:00 to 24:00";
        let b = s.as_bytes();
        if b.len() != 5 || b[2] != b':' || ![b[0], b[1], b[3], b[4]].iter().all(u8::is_ascii_digit)
        {
            return Err(ERR);
        }
        let h = u16::from(b[0] - b'0') * 10 + u16::from(b[1] - b'0');
        let m = u16::from(b[3] - b'0') * 10 + u16::from(b[4] - b'0');
        if m > 59 || h > 24 || (h == 24 && m != 0) {
            return Err(ERR);
        }
        Ok(Self(h * 60 + m))
    }
}

impl fmt::Display for TimeOfDay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02}:{:02}", self.0 / 60, self.0 % 60)
    }
}

/// A calendar date, `YYYY-MM-DD`, from year 0001 to 9999.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date(pub civil::Date);

impl core::str::FromStr for Date {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        const ERR: &str = "expected a date `YYYY-MM-DD`";
        let b = s.as_bytes();
        let digits = |r: core::ops::Range<usize>| b[r].iter().all(u8::is_ascii_digit);
        if b.len() != 10 || b[4] != b'-' || b[7] != b'-' || !digits(0..4) || !digits(5..7) {
            return Err(ERR);
        }
        if !digits(8..10) {
            return Err(ERR);
        }
        let num = |r: core::ops::Range<usize>| s[r].parse::<i16>().map_err(|_| ERR);
        let year = num(0..4)?;
        let month = i8::try_from(num(5..7)?).map_err(|_| ERR)?;
        let day = i8::try_from(num(8..10)?).map_err(|_| ERR)?;
        if year < 1 {
            return Err(ERR);
        }
        civil::Date::new(year, month, day)
            .map(Self)
            .map_err(|_| ERR)
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02}",
            self.0.year(),
            self.0.month(),
            self.0.day()
        )
    }
}

macro_rules! text_serde {
    ($ty:ty, $expecting:literal, $pattern:literal, $description:literal) => {
        impl Serialize for $ty {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct Visitor;
                impl serde::de::Visitor<'_> for Visitor {
                    type Value = $ty;
                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str($expecting)
                    }
                    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<$ty, E> {
                        v.parse().map_err(E::custom)
                    }
                }
                deserializer.deserialize_str(Visitor)
            }
        }

        impl JsonSchema for $ty {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                stringify!($ty).into()
            }

            fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
                schemars::json_schema!({
                    "description": $description,
                    "type": "string",
                    "pattern": $pattern
                })
            }
        }
    };
}

text_serde!(
    TimeOfDay,
    "a time `HH:MM`",
    "^(([01][0-9]|2[0-3]):[0-5][0-9]|24:00)$",
    "A wall-clock time, `HH:MM`, from 00:00 to 24:00."
);
text_serde!(
    Date,
    "a date `YYYY-MM-DD`",
    "^[0-9]{4}-[0-9]{2}-[0-9]{2}$",
    "A calendar date, `YYYY-MM-DD`."
);

/// An inclusive range of dates. `to` unset means the single day `from`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DateRange {
    /// The first day.
    pub from: Date,
    /// The last day, on or after `from`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Date>,
}

impl DateRange {
    /// The last day.
    #[must_use]
    pub fn last(&self) -> Date {
        self.to.unwrap_or(self.from)
    }

    /// Whether the range does not end before it starts.
    #[must_use]
    pub fn is_ordered(&self) -> bool {
        self.from <= self.last()
    }

    /// Whether `date` is in the range.
    #[must_use]
    pub fn contains(&self, date: civil::Date) -> bool {
        self.from.0 <= date && date <= self.last().0
    }
}

/// What happens to processes a scheduled allow let run, when its schedule
/// closes. The engine sends a directive; the agent and the tray act on it
/// (#4, #11).
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum OnWindowClose {
    /// Nothing: they keep running. The default.
    #[default]
    None,
    /// Warn the user.
    Warn,
    /// Warn the user, then terminate them after the grace period.
    WarnThenTerminate,
}

impl OnWindowClose {
    #[allow(clippy::trivially_copy_pass_by_ref)] // serde passes a reference
    const fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

/// The scopes of one rule-set assignment: every one must match for the
/// set's rules to apply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleSetScope {
    /// The rule set, which the policy must reference.
    pub rule_set: RuleSetId,
    /// From 1 to 8 scopes, all of which must match. In an effective policy
    /// (#37) the contributing policy's own scope is added, so up to 9.
    #[schemars(length(min = 1, max = 9))]
    pub scopes: Vec<Scope>,
}

/// A named network location, such as `corporate`: every test must match
/// (#38). The agent evaluates the profiles when the network changes and on
/// every heartbeat, and scopes test the result with `location_profile`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocationProfile {
    /// The profile's name: 1 to 64 characters, letters, digits, `_`, `.`
    /// or `-`. Compared without case.
    #[schemars(length(min = 1, max = 64))]
    pub name: String,
    /// The tests, all of which must match. No `location_profile` tests.
    #[schemars(length(min = 1, max = 32))]
    pub all: Vec<NetworkRef>,
}
