//! The context of one evaluation: the user, device and session (#33).
//!
//! Context criteria (`user.*`, `device.*`, `session.*`) test these facts.
//! As with [`ObjectFacts`](crate::facts::ObjectFacts), this module only
//! defines their shape: the agent collects them (#4), and evaluation never
//! reads the system. A fact that was not collected is `None`, and every
//! criterion on it evaluates to [`Tri::Unknown`](crate::ops::Tri::Unknown).
//!
//! Every fact here is plain data, already known when a decision starts.
//! Facts that cost a lookup at decision time (registry, files, environment
//! blocks), their cost classes and caching, and network, time and
//! scope facts are later parts of #33 and #38.

use crate::model::Field;

/// Everything context criteria can test, for one evaluation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EvaluationContext {
    /// The user the process runs as.
    pub user: UserContext,
    /// The device.
    pub device: DeviceContext,
    /// The session the process runs in.
    pub session: SessionContext,
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
}

/// How a session was started.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
}

impl EvaluationContext {
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
        let (u, d, s) = (&self.user, &self.device, &self.session);
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
            _ => None,
        }
    }
}

/// The canonical form of a SID: `S-1-`, the identifier authority in
/// decimal, then 1 to 15 decimal sub-authorities. The authority may be
/// written in decimal (below 2^32, as Windows writes it) or as `0x` and 12
/// hex digits. `None` if `s` is not a SID.
#[must_use]
pub fn normalize_sid(s: &str) -> Option<String> {
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
    let mut out = format!("S-1-{authority}");
    let mut count = 0usize;
    for part in parts {
        let value = u32::try_from(decimal(part)?).ok()?;
        count += 1;
        if count > 15 {
            return None;
        }
        out.push('-');
        out.push_str(&value.to_string());
    }
    (count > 0).then_some(out)
}

/// A decimal number of 1 to 10 digits, with no sign.
fn decimal(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 10 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// The canonical form of a cloud-directory object ID: a GUID in the
/// `8-4-4-4-12` hex form, lowercase. `None` if `s` is not one.
#[must_use]
pub fn normalize_object_id(s: &str) -> Option<String> {
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

#[cfg(test)]
mod tests;
