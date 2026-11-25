//! The facts only scopes read (#38). The agent collects them (#4); a fact
//! that was not collected is `None`.

use crate::context::{normalize_object_id, normalize_sid};
use crate::library::LibraryId;
use palisade_core::Uuid7;

/// The facts scopes read beyond the user, device, session and network
/// context.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScopeFacts {
    /// The token of the user the process runs as.
    pub process_token: Option<Token>,
    /// The token of the user logged on to the process's session.
    pub session_token: Option<Token>,
    /// The token of the parent process.
    pub parent_token: Option<Token>,
    /// The device's local groups, by name and SID, for `local_group`.
    pub local_groups: Option<Vec<LocalGroup>>,
    /// The agent's trusted time (#18).
    pub time: Option<TrustedTime>,
    /// The device's time zone, as an IANA name such as `Australia/Sydney`.
    pub device_time_zone: Option<String>,
    /// The time zone of the session's user, as an IANA name, if the agent
    /// could read it.
    pub session_time_zone: Option<String>,
    /// The device's Palisade ID.
    pub device_id: Option<Uuid7>,
    /// The device sets (#37) the device is in, as the server worked them
    /// out.
    pub device_sets: Option<Vec<LibraryId>>,
    /// The device sets the connected client device is in, on a
    /// multi-session host.
    pub client_device_sets: Option<Vec<LibraryId>>,
    /// How many instances of the object already run in the session, for
    /// `max_instances_per_session`.
    pub instances_in_session: Option<u32>,
    /// The device's cloud-directory device groups, cached on the device,
    /// for `cloud_device_group`.
    pub device_cloud_groups: Option<CachedGroups>,
}

impl ScopeFacts {
    /// No facts at all.
    pub const EMPTY: Self = Self {
        process_token: None,
        session_token: None,
        parent_token: None,
        local_groups: None,
        time: None,
        device_time_zone: None,
        session_time_zone: None,
        device_id: None,
        device_sets: None,
        client_device_sets: None,
        instances_in_session: None,
        device_cloud_groups: None,
    };
}

/// The agent's time, and whether it trusts it (#18).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TrustedTime {
    /// Seconds since 1970-01-01T00:00:00Z.
    pub unix_secs: i64,
    /// `false` when the agent has flagged the clock's integrity, for
    /// example after it was set back. Scheduled allows then go inactive
    /// and scheduled denies stay active.
    pub trusted: bool,
}

/// A local group on the device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalGroup {
    /// The group's name, such as `Backup Operators`.
    pub name: String,
    /// The group's SID.
    pub sid: String,
}

/// What a user's access token says about them, in the form scopes test.
///
/// Group SIDs are normalised and sorted when the token is built, so a
/// membership test is a binary search, and a test against a sorted set a
/// merge.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Token {
    /// The user's SID, normalised. `TokenUser` is not among the groups.
    sid: Option<String>,
    /// The user SID fact was not a SID.
    sid_malformed: bool,
    account_name: Option<String>,
    /// Sorted by SID: each SID once, deny-only if any copy was.
    groups: Option<Vec<(String, bool)>>,
    /// Some group SID was not a SID, so a missing group is not proof that
    /// the user is not in it.
    malformed: bool,
    cloud: Option<CachedGroups>,
}

/// Cloud-directory group memberships that are not in the token, cached on
/// the device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedGroups {
    /// When the cache was filled, in seconds since 1970-01-01T00:00:00Z.
    pub cached_at: i64,
    /// `(tenant ID, object ID)` pairs, normalised and sorted.
    groups: Vec<(String, String)>,
    /// Some entry was not a pair of GUIDs.
    malformed: bool,
}

impl Token {
    /// A token with no facts.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the user's SID and `DOMAIN\user` account name. A SID that is
    /// not one is recorded as malformed, so no test can rely on it.
    #[must_use]
    pub fn with_user(mut self, sid: Option<&str>, account_name: Option<&str>) -> Self {
        self.sid = sid.and_then(normalize_sid);
        self.sid_malformed = sid.is_some() && self.sid.is_none();
        self.account_name = account_name.map(str::to_owned);
        self
    }

    /// Sets the token's groups: each SID and whether UAC marks it
    /// deny-only (a filtered administrator token). Nested groups are
    /// already resolved in a token.
    #[must_use]
    pub fn with_groups<'a>(mut self, groups: impl IntoIterator<Item = (&'a str, bool)>) -> Self {
        let mut out: Vec<(String, bool)> = Vec::new();
        for (sid, deny_only) in groups {
            match normalize_sid(sid) {
                Some(s) => out.push((s, deny_only)),
                None => self.malformed = true,
            }
        }
        out.sort();
        // Keep one entry per SID; deny-only wins, as the restrictive
        // reading of a contradiction.
        let mut merged: Vec<(String, bool)> = Vec::with_capacity(out.len());
        for (sid, deny_only) in out {
            match merged.last_mut() {
                Some(last) if last.0 == sid => last.1 |= deny_only,
                _ => merged.push((sid, deny_only)),
            }
        }
        self.groups = Some(merged);
        self
    }

    /// Sets the cached cloud-directory groups: `(tenant ID, object ID)`
    /// pairs, cached at `cached_at`.
    #[must_use]
    pub fn with_cloud_groups<'a>(
        mut self,
        cached_at: i64,
        groups: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Self {
        self.cloud = Some(CachedGroups::new(cached_at, groups));
        self
    }

    /// The user's SID, normalised, if it was collected and is a SID.
    #[must_use]
    pub fn sid(&self) -> Option<&str> {
        self.sid.as_deref()
    }

    /// The account name.
    #[must_use]
    pub fn account_name(&self) -> Option<&str> {
        self.account_name.as_deref()
    }

    /// The cached cloud groups.
    #[must_use]
    pub const fn cloud_groups(&self) -> Option<&CachedGroups> {
        self.cloud.as_ref()
    }

    /// Whether any group is deny-only.
    #[must_use]
    pub fn has_deny_only(&self) -> bool {
        self.groups
            .as_ref()
            .is_some_and(|g| g.iter().any(|(_, d)| *d))
    }

    /// How the token holds the canonical SID `sid`: as the user, as a
    /// group, as a deny-only group, or not at all.
    ///
    /// Absence is only proven when both the user SID and the groups were
    /// collected and are well formed: `TokenUser` is not in `TokenGroups`,
    /// so a missing user SID could be the one asked about.
    ///
    /// # Errors
    ///
    /// [`Gap`] when the token cannot say.
    pub fn holds(&self, sid: &str) -> Result<Held, Gap> {
        if self.sid.as_deref() == Some(sid) {
            return Ok(Held::Yes);
        }
        if let Some(groups) = &self.groups {
            // Sorted when the token was built: a binary search.
            if let Ok(i) = groups.binary_search_by(|(s, _)| s.as_str().cmp(sid)) {
                return Ok(if groups[i].1 {
                    Held::DenyOnly
                } else {
                    Held::Yes
                });
            }
        }
        self.absent()
    }

    /// `No` if the token proves absence, otherwise the gap.
    fn absent(&self) -> Result<Held, Gap> {
        if self.sid_malformed || self.malformed {
            Err(Gap::Malformed)
        } else if self.sid.is_none() || self.groups.is_none() {
            Err(Gap::Missing)
        } else {
            Ok(Held::No)
        }
    }

    /// Whether the user SID or any group SID is in `sids`, which must be
    /// sorted: a merge of two sorted lists, in `O(groups + sids)`.
    ///
    /// # Errors
    ///
    /// [`Gap`] when the token cannot say.
    pub fn holds_any_of(&self, sids: &[String]) -> Result<Held, Gap> {
        let within = |s: &str| sids.binary_search_by(|x| x.as_str().cmp(s)).is_ok();
        if self.sid.as_deref().is_some_and(within) {
            return Ok(Held::Yes);
        }
        let mut best = None;
        if let Some(groups) = &self.groups {
            let (mut i, mut j) = (0, 0);
            while i < groups.len() && j < sids.len() {
                match groups[i].0.as_str().cmp(sids[j].as_str()) {
                    core::cmp::Ordering::Less => i += 1,
                    core::cmp::Ordering::Greater => j += 1,
                    core::cmp::Ordering::Equal => {
                        if !groups[i].1 {
                            return Ok(Held::Yes);
                        }
                        best = Some(Held::DenyOnly);
                        i += 1;
                        j += 1;
                    }
                }
            }
        }
        best.map_or_else(|| self.absent(), Ok)
    }

    /// Whether the user SID or any group SID satisfies `test`, in the same
    /// form as [`holds`](Self::holds).
    ///
    /// # Errors
    ///
    /// [`Gap`] when the token cannot say.
    pub fn holds_any(&self, test: impl Fn(&str) -> bool) -> Result<Held, Gap> {
        if self.sid.as_deref().is_some_and(&test) {
            return Ok(Held::Yes);
        }
        let mut best = Held::No;
        if let Some(groups) = &self.groups {
            for (sid, deny_only) in groups {
                if test(sid) {
                    if !deny_only {
                        return Ok(Held::Yes);
                    }
                    best = Held::DenyOnly;
                }
            }
        }
        if best == Held::DenyOnly {
            return Ok(best);
        }
        self.absent()
    }
}

/// Why a token cannot say whether it holds a SID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gap {
    /// The user SID or the groups were not collected.
    Missing,
    /// The user SID or a group SID was not a SID.
    Malformed,
}

impl CachedGroups {
    /// Whether the cache holds any group whose object ID is in `objects`,
    /// which must be sorted: `O(cache × log objects)`. `None` if it may
    /// hold one among malformed entries.
    #[must_use]
    pub fn contains_any(&self, objects: &[String]) -> Option<bool> {
        let found = self
            .groups
            .iter()
            .any(|(_, o)| objects.binary_search(o).is_ok());
        if !found && self.malformed {
            None
        } else {
            Some(found)
        }
    }

    /// A cache of `(tenant ID, object ID)` pairs filled at `cached_at`, in
    /// seconds since 1970-01-01T00:00:00Z. A pair that is not two GUIDs is
    /// recorded as malformed, so absence can no longer be proven.
    #[must_use]
    pub fn new<'a>(cached_at: i64, groups: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut malformed = false;
        let mut out = Vec::new();
        for (tenant, object) in groups {
            match (normalize_object_id(tenant), normalize_object_id(object)) {
                (Some(t), Some(o)) => out.push((t, o)),
                _ => malformed = true,
            }
        }
        out.sort();
        out.dedup();
        Self {
            cached_at,
            groups: out,
            malformed,
        }
    }

    /// Whether the cache holds the group, `None` if it may hold it among
    /// malformed entries. `tenant` of `None` matches any tenant.
    #[must_use]
    pub fn contains(&self, tenant: Option<&str>, object: &str) -> Option<bool> {
        let found = match tenant {
            // Sorted by tenant, then object: a binary search.
            Some(t) => self
                .groups
                .binary_search_by(|(gt, go)| (gt.as_str(), go.as_str()).cmp(&(t, object)))
                .is_ok(),
            None => self.groups.iter().any(|(_, o)| o == object),
        };
        if !found && self.malformed {
            None
        } else {
            Some(found)
        }
    }
}

/// How a token holds a SID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Held {
    /// Enabled, or the user's own SID.
    Yes,
    /// Present but deny-only: UAC filtered it out of the token.
    DenyOnly,
    /// Not present.
    No,
}
