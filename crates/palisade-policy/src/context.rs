//! The context of one evaluation: the user, device and session (#33).
//!
//! Context criteria (`user.*`, `device.*`, `session.*`) test these facts.
//! As with [`ObjectFacts`](crate::facts::ObjectFacts), this module only
//! defines their shape: the agent collects them (#4), and evaluation never
//! reads the system. A fact that was not collected is `None`, and every
//! criterion on it evaluates to [`Tri::Unknown`](crate::ops::Tri::Unknown).
//!
//! Every fact here is plain data, already known when a decision starts,
//! and the caller supplies all of it: [`EvaluationContext::new`] knows
//! nothing, so every context criterion is unknown until the caller fills
//! the facts in. Collecting them on the endpoint is #4. The caller (the
//! agent) collects the network facts on network changes and heartbeats,
//! and converts the time facts from its trusted clock (#18) into the clock
//! the policy's `time_zone_basis` names; nothing here reads the host clock.
//! When the clock cannot be trusted it leaves the time facts out, so every time criterion is unknown: an allow
//! that depends on the time fails closed. Facts the policy probes at a
//! named target (environment variables, the registry, files and folders)
//! are in [`probe`] (#329). The facts only scopes read ([`ScopeFacts`]) are
//! part of rule scoping (#38).

use std::net::IpAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::model::Field;
use crate::scope::ScopeFacts;

pub mod cmdline;
pub mod probe;
pub use probe::{Probe, ProbeTarget, Probes, probe_targets};

/// Everything context criteria can test, for one evaluation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EvaluationContext {
    /// The user the process runs as.
    pub user: UserContext,
    /// The device.
    pub device: DeviceContext,
    /// The session the process runs in.
    pub session: SessionContext,
    /// The device's network location (#33, #38).
    pub network: NetworkContext,
    /// The facts only scopes read (#38): the subjects' tokens and cached
    /// groups, trusted time, time zones, set memberships and instance
    /// counts.
    pub scope: ScopeFacts,
    /// The time of the evaluation, for time criteria (#33).
    pub time: TimeContext,
    /// What the agent found at the environment variables, registry keys and
    /// values, files and folders the policy probes (#329,
    /// [`probe_targets`]).
    pub probes: Probes,
    /// The process being started: its command line (#329).
    pub process: ProcessContext,
}

/// The process a decision is about, as the agent saw it at creation (#8).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcessContext {
    /// The command line, exactly as captured.
    pub command_line: Option<String>,
    /// Its arguments, split by [`cmdline::split_args`]. Set together with
    /// `command_line` by [`ProcessContext::with_command_line`].
    pub args: Option<Vec<String>>,
}

impl ProcessContext {
    /// No process facts: every `process.*` criterion is unknown.
    pub const EMPTY: Self = Self {
        command_line: None,
        args: None,
    };

    /// The command line, and its arguments split from it.
    #[must_use]
    pub fn with_command_line(command_line: impl Into<String>) -> Self {
        let command_line = command_line.into();
        Self {
            args: Some(cmdline::split_args(&command_line)),
            command_line: Some(command_line),
        }
    }
}

/// The user the process runs as, from its token and the directory.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UserContext {
    /// The user's SID, such as `S-1-5-21-…-1001`.
    pub sid: Option<String>,
    /// The account name as `DOMAIN\user`.
    pub account_name: Option<String>,
    /// The user principal name, such as `user@example.org`.
    pub upn: Option<String>,
    /// Every group in the token, as SIDs, including groups that UAC marks
    /// deny-only in a filtered token, and the user's cloud-directory
    /// groups, as object IDs. Nested groups are already resolved (#4).
    pub groups: Option<Vec<String>>,
    /// The SID of the user's primary group.
    pub primary_group: Option<String>,
    /// The token holds the local Administrators group, enabled or filtered.
    pub is_admin: Option<bool>,
    /// The token is elevated.
    pub is_elevated: Option<bool>,
    /// The user is a service account.
    pub is_service_account: Option<bool>,
    /// The user is the local system account.
    pub is_system: Option<bool>,
    /// The integrity level of the process token.
    pub integrity_level: Option<IntegrityLevel>,
    /// The distinguished name of the user's directory object, such as
    /// `CN=alice,OU=Finance,DC=corp,DC=example`. `user.ou` tests the unit
    /// it is in.
    pub dn: Option<String>,
}

/// The device the decision is made on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceContext {
    /// The host name.
    pub hostname: Option<String>,
    /// The fully qualified domain name.
    pub fqdn: Option<String>,
    /// The DNS name of the domain.
    pub domain: Option<String>,
    /// The NetBIOS name.
    pub netbios: Option<String>,
    /// The directory site.
    pub ad_site: Option<String>,
    /// The computer groups, as SIDs, and cloud-directory device groups, as
    /// object IDs.
    pub groups: Option<Vec<String>>,
    /// The Palisade tags assigned to the device.
    pub tags: Option<Vec<String>>,
    /// The operating system version, such as `10.0.22631.4460`.
    pub os_version: Option<String>,
    /// The operating system edition.
    pub os_edition: Option<String>,
    /// The processor architecture, such as `x64` or `arm64`.
    pub arch: Option<String>,
    /// The device runs a server edition.
    pub is_server: Option<bool>,
    /// The device is a domain controller.
    pub is_domain_controller: Option<bool>,
    /// The device is a laptop.
    pub is_laptop: Option<bool>,
    /// The device is a virtual desktop.
    pub is_vdi: Option<bool>,
    /// The device is a multi-session terminal server.
    pub is_terminal_server: Option<bool>,
    /// The operating system build number, such as `22631`.
    pub os_build: Option<u32>,
    /// The distinguished name of the device's computer object in the
    /// directory, such as `CN=WS-0042,OU=Finance,DC=corp,DC=example,DC=org`.
    /// `device.ou` tests the unit it is in.
    pub dn: Option<String>,
    /// How far the device has booted (#39). Drivers loaded in
    /// [`BootPhase::Early`] follow the unknown policy's
    /// `driver_boot_policy`.
    pub boot_phase: Option<BootPhase>,
    /// Whether the application containment component (#14) is installed
    /// and running. The unknown policy's `restrict` level blocks instead
    /// unless this is `Some(true)` (#39).
    pub containment_available: Option<bool>,
}

/// How far the device has booted, as the agent reports it (#39).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BootPhase {
    /// Before the agent had fully started: boot-start drivers, which #6
    /// and #8 handle, not the unknown-application policy.
    Early,
    /// The agent is running.
    Running,
}

/// The session the process runs in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionContext {
    /// How the session was started.
    pub session_type: Option<SessionType>,
    /// The host name of the connected client, on a multi-session host.
    pub client_hostname: Option<String>,
    /// The session is remote.
    pub is_remote: Option<bool>,
    /// The session ID.
    pub id: Option<u32>,
    /// The address of the connected client, on a multi-session host.
    pub client_ip: Option<IpAddr>,
}

/// The device's network location, as the agent last observed it (#38).
///
/// The agent evaluates the location on network change events and on every
/// heartbeat, and keeps the previous location until a new one is stable
/// ([`LocationTracker`](crate::scope::LocationTracker)).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkContext {
    /// The addresses of the local interfaces.
    pub addresses: Option<Vec<IpAddr>>,
    /// The hardware addresses of the local interfaces.
    pub macs: Option<Vec<[u8; 6]>>,
    /// The connection-specific DNS suffixes.
    pub dns_suffixes: Option<Vec<String>>,
    /// The hardware addresses of the default gateways.
    pub gateway_macs: Option<Vec<[u8; 6]>>,
    /// Whether the management server answered the last check.
    pub server_reachable: Option<bool>,
    /// The names of the location profiles that are active, after the
    /// debounce.
    pub locations: Option<Vec<String>>,
}

/// When the evaluation happens, in the clock the policy's
/// `time_zone_basis` names. The agent fills this from its trusted clock,
/// and leaves it empty when the clock cannot be trusted (#18).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimeContext {
    /// The day of the week.
    pub weekday: Option<Weekday>,
    /// Minutes since midnight, 0 to 1439.
    pub minute_of_day: Option<u16>,
    /// The date.
    pub date: Option<Date>,
}

/// The integrity level of a process token, from lowest to highest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IntegrityLevel {
    /// Untrusted.
    Untrusted,
    /// Low, as for a sandboxed process.
    Low,
    /// Medium: a standard user.
    Medium,
    /// Medium plus.
    MediumPlus,
    /// High: an elevated administrator.
    High,
    /// System.
    System,
    /// Protected process.
    Protected,
}

impl IntegrityLevel {
    /// Every level, from lowest to highest.
    pub const ALL: [Self; 7] = [
        Self::Untrusted,
        Self::Low,
        Self::Medium,
        Self::MediumPlus,
        Self::High,
        Self::System,
        Self::Protected,
    ];

    /// The name a criterion value uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Untrusted => "untrusted",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::MediumPlus => "medium_plus",
            Self::High => "high",
            Self::System => "system",
            Self::Protected => "protected",
        }
    }

    /// The level with this name, exactly as [`Self::as_str`] writes it.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.as_str() == name)
    }
}

/// A day of the week.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    /// Every day, from Monday.
    pub const ALL: [Self; 7] = [
        Self::Mon,
        Self::Tue,
        Self::Wed,
        Self::Thu,
        Self::Fri,
        Self::Sat,
        Self::Sun,
    ];

    /// The name a criterion value uses: `mon` to `sun`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mon => "mon",
            Self::Tue => "tue",
            Self::Wed => "wed",
            Self::Thu => "thu",
            Self::Fri => "fri",
            Self::Sat => "sat",
            Self::Sun => "sun",
        }
    }

    /// The day with this name, exactly as [`Self::as_str`] writes it.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|d| d.as_str() == name)
    }
}

/// A calendar date in the proleptic Gregorian calendar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date {
    year: u16,
    month: u8,
    day: u8,
}

impl Date {
    /// The date, if it exists: years 1 to 9999.
    #[must_use]
    pub const fn new(year: u16, month: u8, day: u8) -> Option<Self> {
        if year == 0 || year > 9999 || month == 0 || month > 12 || day == 0 {
            return None;
        }
        let leap =
            year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
        let days = match month {
            2 if leap => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        };
        if day > days {
            None
        } else {
            Some(Self { year, month, day })
        }
    }

    /// Reads `YYYY-MM-DD`, with exactly four, two and two digits.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
            return None;
        }
        let digits = |r: core::ops::Range<usize>| -> Option<u16> {
            let part = &s[r];
            if !part.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            part.parse().ok()
        };
        let year = digits(0..4)?;
        let month = u8::try_from(digits(5..7)?).ok()?;
        let day = u8::try_from(digits(8..10)?).ok()?;
        Self::new(year, month, day)
    }
}

impl core::fmt::Display for Date {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

/// Reads a time of day, `HH:MM` with a 24-hour clock, as minutes since
/// midnight.
#[must_use]
pub fn parse_time_of_day(s: &str) -> Option<u16> {
    let b = s.as_bytes();
    if b.len() != 5 || b[2] != b':' || !b[..2].iter().chain(&b[3..]).all(u8::is_ascii_digit) {
        return None;
    }
    let hours: u16 = s[..2].parse().ok()?;
    let minutes: u16 = s[3..].parse().ok()?;
    (hours < 24 && minutes < 60).then_some(hours * 60 + minutes)
}

/// How a session was started.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SessionType {
    /// The physical console.
    Console,
    /// A remote desktop session.
    Rdp,
    /// A remote shell, such as a remote PowerShell session.
    RemoteShell,
    /// A service.
    Service,
    /// A batch job, such as a scheduled task.
    Batch,
    /// A network logon.
    Network,
}

impl SessionType {
    /// Every session type.
    pub const ALL: [Self; 6] = [
        Self::Console,
        Self::Rdp,
        Self::RemoteShell,
        Self::Service,
        Self::Batch,
        Self::Network,
    ];

    /// The name a criterion value uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Console => "console",
            Self::Rdp => "rdp",
            Self::RemoteShell => "remote_shell",
            Self::Service => "service",
            Self::Batch => "batch",
            Self::Network => "network",
        }
    }

    /// The session type with this name, exactly as [`Self::as_str`] writes it.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == name)
    }
}

/// A context fact, as a criterion reads it.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ContextFact<'a> {
    /// One string.
    Text(&'a str),
    /// The account name and the user principal name, whichever are known.
    Names(Option<&'a str>, Option<&'a str>),
    /// A set of strings.
    Set(&'a [String]),
    /// A yes-or-no fact.
    Bool(bool),
    /// A session type.
    Session(SessionType),
    /// A whole number.
    Number(u64),
    /// An integrity level.
    Level(IntegrityLevel),
    /// One IP address.
    Ip(IpAddr),
    /// A set of IP addresses.
    Ips(&'a [IpAddr]),
    /// A set of MAC addresses.
    Macs(&'a [[u8; 6]]),
    /// A day of the week.
    Weekday(Weekday),
    /// Minutes since midnight.
    Minute(u16),
    /// The arguments of a command line (#329).
    Args(&'a [String]),
    /// A date.
    Date(Date),
}

impl EvaluationContext {
    /// No facts at all, as a constant: every context criterion evaluates
    /// to unknown.
    pub const EMPTY: Self = Self {
        user: UserContext {
            sid: None,
            account_name: None,
            upn: None,
            groups: None,
            primary_group: None,
            is_admin: None,
            is_elevated: None,
            is_service_account: None,
            is_system: None,
            integrity_level: None,
            dn: None,
        },
        device: DeviceContext {
            hostname: None,
            fqdn: None,
            domain: None,
            netbios: None,
            ad_site: None,
            groups: None,
            tags: None,
            os_version: None,
            os_edition: None,
            arch: None,
            is_server: None,
            is_domain_controller: None,
            is_laptop: None,
            is_vdi: None,
            is_terminal_server: None,
            os_build: None,
            dn: None,
            boot_phase: None,
            containment_available: None,
        },
        session: SessionContext {
            session_type: None,
            client_hostname: None,
            is_remote: None,
            id: None,
            client_ip: None,
        },
        network: NetworkContext {
            addresses: None,
            macs: None,
            dns_suffixes: None,
            gateway_macs: None,
            server_reachable: None,
            locations: None,
        },
        scope: ScopeFacts::EMPTY,
        time: TimeContext {
            weekday: None,
            minute_of_day: None,
            date: None,
        },
        probes: Probes::EMPTY,
        process: ProcessContext::EMPTY,
    };

    /// No facts at all: every context criterion evaluates to unknown.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The fact a context field tests, or `None` if it was not collected or
    /// `field` is not a context field.
    pub(crate) fn fact(&self, field: Field) -> Option<ContextFact<'_>> {
        fn text(v: &Option<String>) -> Option<ContextFact<'_>> {
            v.as_deref().map(ContextFact::Text)
        }
        fn set(v: &Option<Vec<String>>) -> Option<ContextFact<'_>> {
            v.as_deref().map(ContextFact::Set)
        }
        fn flag(v: Option<bool>) -> Option<ContextFact<'static>> {
            v.map(ContextFact::Bool)
        }
        let (u, d, s, n, t) = (
            &self.user,
            &self.device,
            &self.session,
            &self.network,
            &self.time,
        );
        match field {
            Field::UserSid => text(&u.sid),
            Field::UserName => match (u.account_name.as_deref(), u.upn.as_deref()) {
                (None, None) => None,
                (account, upn) => Some(ContextFact::Names(account, upn)),
            },
            Field::UserGroups => set(&u.groups),
            Field::UserPrimaryGroup => text(&u.primary_group),
            Field::UserIsAdmin => flag(u.is_admin),
            Field::UserIsElevated => flag(u.is_elevated),
            Field::UserIsServiceAccount => flag(u.is_service_account),
            Field::UserIsSystem => flag(u.is_system),
            Field::DeviceHostname => text(&d.hostname),
            Field::DeviceFqdn => text(&d.fqdn),
            Field::DeviceDomain => text(&d.domain),
            Field::DeviceNetbios => text(&d.netbios),
            Field::DeviceAdSite => text(&d.ad_site),
            Field::DeviceGroups => set(&d.groups),
            Field::DeviceTags => set(&d.tags),
            Field::DeviceOsVersion => text(&d.os_version),
            Field::DeviceOsEdition => text(&d.os_edition),
            Field::DeviceArch => text(&d.arch),
            Field::DeviceIsServer => flag(d.is_server),
            Field::DeviceIsDomainController => flag(d.is_domain_controller),
            Field::DeviceIsLaptop => flag(d.is_laptop),
            Field::DeviceIsVdi => flag(d.is_vdi),
            Field::DeviceIsTerminalServer => flag(d.is_terminal_server),
            Field::SessionType => s.session_type.map(ContextFact::Session),
            Field::SessionClientHostname => text(&s.client_hostname),
            Field::SessionIsRemote => flag(s.is_remote),
            Field::UserIntegrityLevel => u.integrity_level.map(ContextFact::Level),
            Field::UserOu => text(&u.dn),
            Field::DeviceOu => text(&d.dn),
            Field::DeviceOsBuild => d.os_build.map(|v| ContextFact::Number(v.into())),
            Field::SessionId => s.id.map(|v| ContextFact::Number(v.into())),
            Field::SessionClientIp => s.client_ip.map(ContextFact::Ip),
            Field::NetIp => n.addresses.as_deref().map(ContextFact::Ips),
            Field::NetMac => n.macs.as_deref().map(ContextFact::Macs),
            Field::NetDnsSuffix => set(&n.dns_suffixes),
            Field::NetConnectedToServer => flag(n.server_reachable),
            Field::NetLocation => set(&n.locations),
            Field::TimeWeekday => t.weekday.map(ContextFact::Weekday),
            // A minute past the end of the day is not a time of day.
            Field::TimeLocalTime => t
                .minute_of_day
                .filter(|m| *m < 24 * 60)
                .map(ContextFact::Minute),
            Field::TimeDate => t.date.map(ContextFact::Date),
            Field::ProcessCommandLine => text(&self.process.command_line),
            Field::ProcessArgv => self.process.args.as_deref().map(ContextFact::Args),
            _ => None,
        }
    }
}

/// The canonical form of a SID (MS-DTYP 2.4.2.1): `S-1-`, the identifier
/// authority, then 1 to 15 decimal sub-authorities without leading zeros.
/// The authority is written in decimal when it is below 2^32, and otherwise
/// as `0x` and 12 lowercase hex digits, as Windows writes it. On input it
/// may be written either way, in any case, and decimal numbers may have
/// leading zeros. The result is itself canonical: normalising it again
/// gives the same text. `None` if `s` is not a SID.
#[must_use]
pub fn normalize_sid(s: &str) -> Option<String> {
    let mut out = String::new();
    normalize_sid_into(s, &mut out).then_some(out)
}

/// Writes the canonical form of the SID `s` to `out`, after clearing it,
/// and returns whether `s` is a SID. Allocates only to grow `out`.
pub(crate) fn normalize_sid_into(s: &str, out: &mut String) -> bool {
    use core::fmt::Write as _;
    out.clear();
    parse_sid(s, out, &mut |out, v| {
        let _ = write!(out, "{v}");
    })
    .is_some()
}

/// Parses a SID, writing its canonical form to `out` with `num` writing
/// each decimal number.
fn parse_sid(s: &str, out: &mut String, num: &mut dyn FnMut(&mut String, u64)) -> Option<()> {
    use core::fmt::Write as _;
    let mut parts = s.split('-');
    if !parts.next()?.eq_ignore_ascii_case("s") || parts.next()? != "1" {
        return None;
    }
    let authority = parts.next()?;
    let authority: u64 = if let Some(hex) = authority
        .strip_prefix("0x")
        .or_else(|| authority.strip_prefix("0X"))
    {
        if hex.len() != 12 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        u64::from_str_radix(hex, 16).ok()?
    } else {
        let value = decimal(authority)?;
        if value >= 1 << 32 {
            return None;
        }
        value
    };
    out.push_str("S-1-");
    if authority < 1 << 32 {
        num(out, authority);
    } else {
        let _ = write!(out, "0x{authority:012x}");
    }
    let mut count = 0usize;
    for part in parts {
        let value = u32::try_from(decimal(part)?).ok()?;
        count += 1;
        if count > 15 {
            return None;
        }
        out.push('-');
        num(out, u64::from(value));
    }
    (count > 0).then_some(())
}

/// A decimal number with no sign: one or more digits, of which at most 10
/// are significant. Leading zeros are ignored.
fn decimal(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let significant = s.trim_start_matches('0');
    if significant.is_empty() {
        return Some(0);
    }
    if significant.len() > 10 {
        return None;
    }
    significant.parse().ok()
}

/// The canonical form of a cloud-directory object ID: a GUID in the
/// `8-4-4-4-12` hex form, lowercase. `None` if `s` is not one.
#[must_use]
pub fn normalize_object_id(s: &str) -> Option<String> {
    if s.len() != 36 {
        return None;
    }
    let groups: Vec<&str> = s.split('-').collect();
    let lengths = [8, 4, 4, 4, 12];
    let ok = groups.len() == lengths.len()
        && groups
            .iter()
            .zip(lengths)
            .all(|(g, n)| g.len() == n && g.bytes().all(|b| b.is_ascii_hexdigit()));
    ok.then(|| s.to_ascii_lowercase())
}

/// The canonical form of a member of a principal set: a SID or an object ID.
#[must_use]
pub fn normalize_principal(s: &str) -> Option<String> {
    normalize_sid(s).or_else(|| normalize_object_id(s))
}

/// Writes the canonical form of the principal `s` to `out`, after clearing
/// it, and returns whether `s` is a SID or an object ID. Allocates only to
/// grow `out`.
pub(crate) fn normalize_principal_into(s: &str, out: &mut String) -> bool {
    if normalize_sid_into(s, out) {
        return true;
    }
    out.clear();
    if is_object_id(s) {
        out.extend(s.chars().map(|c| c.to_ascii_lowercase()));
        true
    } else {
        false
    }
}

/// Whether `s` is an object ID in the `8-4-4-4-12` hex form.
fn is_object_id(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

#[cfg(test)]
mod tests;
