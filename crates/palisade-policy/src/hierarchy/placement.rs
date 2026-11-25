//! Automatic placement: which group a device belongs in (#37).
//!
//! Each tenant has an ordered list of placement rules. The first rule whose
//! conditions all match places the device in its target group. Every list
//! ends with an implicit catch-all that places every other device in the
//! tenant's built-in `unassigned` group, so the catch-all cannot be deleted
//! or reordered. A rule may target only an ordinary group of the same
//! tenant that has not opted out (`allow_auto_assignment: false`); `staging`,
//! `unmanaged` and `unassigned` cannot be targets (`unassigned` is reached
//! through the catch-all).
//!
//! A device whose current group has opted out is never moved
//! ([`PlacementOutcome::Kept`]). Placement runs on first contact and on
//! every reconnect, and on a change of signed-in user only if the tenant
//! sets `place_on_user_change` ([`PlacementTrigger`]).
//!
//! # Conditions
//!
//! Each set condition must match; within one condition, any value may.
//! Text is compared without case.
//!
//! - `directory_ou`: the device's directory OU equals the value or is
//!   below it (`OU=Laptops,DC=example,DC=org` includes
//!   `OU=Sales,OU=Laptops,DC=example,DC=org`).
//! - `directory_groups`: the device is in one of the groups (SIDs or object
//!   IDs, canonical form).
//! - `hostname`: a wildcard with `*` (any run of characters) and `?` (one).
//! - `networks`: the device's IP address is in one of the CIDRs (IPv4 or
//!   IPv6).
//! - `tags`: the device has every tag.
//! - `os`: the device's OS name starts with one of the values.
//!
//! A fact the device did not report never matches, so an unknown device
//! falls through to `unassigned`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::limits::MAX_PLACEMENT_RULES;
use super::validate::NodeInfo;
use super::{Builtin, HierarchyCode, HierarchyError, NodeId, NodeKind, herr};
use crate::context::normalize_principal;
use palisade_core::Uuid7;

/// Most values in one placement condition.
pub const MAX_CONDITION_VALUES: usize = 100;

/// One placement rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementRule {
    /// Stable ID.
    pub id: Uuid7,
    /// The tenant.
    pub tenant: NodeId,
    /// The position: lower first, unique in the tenant.
    pub order: u32,
    /// The group a matching device is placed in.
    pub target: NodeId,
    /// What a device must match.
    pub conditions: PlacementConditions,
}

/// The conditions of a placement rule. Every condition that is set must
/// match, and at least one must be set.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementConditions {
    /// Directory OUs, as distinguished names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub directory_ou: Vec<String>,
    /// Directory groups, by SID or object ID.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub directory_groups: Vec<String>,
    /// Hostname wildcards.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostname: Vec<String>,
    /// CIDRs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub networks: Vec<String>,
    /// Tags, all required.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// OS name prefixes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub os: Vec<String>,
}

impl PlacementConditions {
    fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// What a device reported. A fact it did not report is `None` or empty.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlacementFacts {
    /// The directory OU, as a distinguished name.
    pub directory_ou: Option<String>,
    /// The directory groups, by SID or object ID.
    pub directory_groups: Vec<String>,
    /// The hostname.
    pub hostname: Option<String>,
    /// The IP address.
    pub ip: Option<IpAddr>,
    /// The tags.
    pub tags: Vec<String>,
    /// The OS name, such as `Windows 11 Enterprise`.
    pub os: Option<String>,
}

/// Why placement runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PlacementTrigger {
    /// The device's first contact.
    FirstContact,
    /// A reconnect.
    Reconnect,
    /// A change of signed-in user.
    UserChange,
}

/// The result of placement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlacementOutcome {
    /// The device belongs in `group`. `rule` is the placement rule that
    /// matched, or `None` for the catch-all.
    Place {
        /// The group.
        group: NodeId,
        /// The rule, or `None` for the catch-all.
        rule: Option<Uuid7>,
    },
    /// The device stays where it is: its group opted out of placement.
    Kept,
    /// Placement does not run for this trigger in this tenant.
    NotEvaluated,
}

/// Checks every placement rule. Returns each tenant's rules in order.
pub(super) fn check(
    rules: &[PlacementRule],
    nodes: &BTreeMap<NodeId, NodeInfo>,
    errors: &mut Vec<HierarchyError>,
) -> BTreeMap<NodeId, Vec<PlacementRule>> {
    let mut out: BTreeMap<NodeId, Vec<PlacementRule>> = BTreeMap::new();
    let mut ids = BTreeMap::new();
    let mut orders: BTreeMap<(NodeId, u32), usize> = BTreeMap::new();
    for (i, r) in rules.iter().enumerate() {
        let base = format!("/placement/{i}");
        if let Some(first) = ids.insert(r.id, i) {
            errors.push(herr(
                HierarchyCode::DuplicateId,
                format!("{base}/id"),
                format!(
                    "placement rule ID {} is already used by /placement/{first}",
                    r.id
                ),
            ));
        }
        let mut bad = |path: &str, message: String| {
            errors.push(herr(
                HierarchyCode::InvalidPlacement,
                format!("{base}{path}"),
                message,
            ));
        };
        match nodes.get(&r.tenant) {
            Some(t) if t.node.kind == NodeKind::Tenant => {}
            _ => bad("/tenant", format!("node {} is not a tenant", r.tenant)),
        }
        if let Some(first) = orders.insert((r.tenant, r.order), i) {
            bad(
                "/order",
                format!(
                    "order {} is already used in this tenant by /placement/{first}",
                    r.order
                ),
            );
        }
        match nodes.get(&r.target) {
            None => bad("/target", format!("node {} does not exist", r.target)),
            Some(t) => {
                if t.node.kind != NodeKind::Group || t.tenant != Some(r.tenant) {
                    bad(
                        "/target",
                        format!("`{}` is not a group of this tenant", t.node.name),
                    );
                } else if t.node.builtin.is_some() {
                    bad(
                        "/target",
                        format!(
                            "`{}` is built in; devices reach `unassigned` through the catch-all, and cannot be placed in `staging` or `unmanaged`",
                            t.node.name
                        ),
                    );
                } else if t.node.allow_auto_assignment == Some(false) {
                    bad(
                        "/target",
                        format!("group `{}` has opted out of placement", t.node.name),
                    );
                }
            }
        }
        let c = &r.conditions;
        if c.is_empty() {
            bad(
                "/conditions",
                "a placement rule needs at least one condition; every other device reaches the catch-all".to_owned(),
            );
        }
        for (key, values) in [
            ("directory_ou", &c.directory_ou),
            ("directory_groups", &c.directory_groups),
            ("hostname", &c.hostname),
            ("networks", &c.networks),
            ("tags", &c.tags),
            ("os", &c.os),
        ] {
            if values.len() > MAX_CONDITION_VALUES {
                bad(
                    &format!("/conditions/{key}"),
                    format!("at most {MAX_CONDITION_VALUES} values"),
                );
            }
            for (j, v) in values.iter().enumerate() {
                let problem = if v.trim().is_empty()
                    || v.chars()
                        .any(|c| c.is_control() || crate::validate::is_bidi_control(c))
                    || v.len() > 2048
                {
                    Some("values are 1 to 2048 bytes with no control or bidirectional formatting characters".to_owned())
                } else if key == "directory_groups" && normalize_principal(v).is_none() {
                    Some("not a SID or an object ID".to_owned())
                } else if key == "networks" && parse_cidr(v).is_none() {
                    Some("not a CIDR such as `10.0.0.0/8` or `2001:db8::/32`".to_owned())
                } else {
                    None
                };
                if let Some(problem) = problem {
                    bad(&format!("/conditions/{key}/{j}"), problem);
                }
            }
        }
        out.entry(r.tenant).or_default().push(r.clone());
    }
    for (tenant, list) in &mut out {
        if list.len() > MAX_PLACEMENT_RULES {
            errors.push(herr(
                HierarchyCode::TooMany,
                "/placement",
                format!(
                    "tenant {tenant} has {} placement rules; at most {MAX_PLACEMENT_RULES} are allowed",
                    list.len()
                ),
            ));
        }
        list.sort_by_key(|r| (r.order, r.id));
    }
    out
}

impl super::ValidatedHierarchy {
    /// Places a device in `tenant`. `current` is its primary group, if it
    /// has one.
    ///
    /// # Errors
    ///
    /// `unknown_node` if `tenant` is not a tenant.
    pub fn place(
        &self,
        tenant: NodeId,
        current: Option<NodeId>,
        facts: &PlacementFacts,
        trigger: PlacementTrigger,
    ) -> Result<PlacementOutcome, HierarchyError> {
        let t = self
            .nodes
            .get(&tenant)
            .filter(|t| t.node.kind == NodeKind::Tenant)
            .ok_or_else(|| {
                herr(
                    HierarchyCode::UnknownNode,
                    "",
                    format!("node {tenant} is not a tenant"),
                )
            })?;
        if trigger == PlacementTrigger::UserChange && !self.place_on_user_change(tenant) {
            return Ok(PlacementOutcome::NotEvaluated);
        }
        if let Some(group) = current.and_then(|c| self.nodes.get(&c)) {
            if group.tenant == Some(tenant)
                && (group.node.allow_auto_assignment == Some(false)
                    || group.node.builtin == Some(Builtin::Unmanaged))
            {
                return Ok(PlacementOutcome::Kept);
            }
        }
        for rule in self.placement.get(&tenant).map_or(&[][..], Vec::as_slice) {
            if matches(&rule.conditions, facts) {
                return Ok(PlacementOutcome::Place {
                    group: rule.target,
                    rule: Some(rule.id),
                });
            }
        }
        let unassigned = self.unassigned.get(&t.node.id).copied().ok_or_else(|| {
            herr(
                HierarchyCode::InvalidBuiltin,
                t.path(),
                "the tenant has no `unassigned` group",
            )
        })?;
        Ok(PlacementOutcome::Place {
            group: unassigned,
            rule: None,
        })
    }
}

/// Whether every set condition matches.
#[must_use]
pub fn matches(c: &PlacementConditions, f: &PlacementFacts) -> bool {
    let lower = |s: &str| s.to_lowercase();
    let ou = c.directory_ou.is_empty()
        || f.directory_ou.as_deref().is_some_and(|ou| {
            let ou = lower(ou);
            c.directory_ou
                .iter()
                .any(|want| ou_within(&ou, &lower(want)))
        });
    let groups = c.directory_groups.is_empty() || {
        let have: BTreeSet<String> = f
            .directory_groups
            .iter()
            .filter_map(|g| normalize_principal(g))
            .collect();
        c.directory_groups
            .iter()
            .filter_map(|g| normalize_principal(g))
            .any(|g| have.contains(&g))
    };
    let host = c.hostname.is_empty()
        || f.hostname
            .as_deref()
            .filter(|h| h.len() <= MAX_HOSTNAME_BYTES)
            .is_some_and(|h| c.hostname.iter().any(|p| wildcard(&lower(p), &lower(h))));
    let net = c.networks.is_empty()
        || f.ip.is_some_and(|ip| {
            c.networks
                .iter()
                .filter_map(|n| parse_cidr(n))
                .any(|n| n.contains(ip))
        });
    let tags = c.tags.is_empty() || {
        let have: BTreeSet<String> = f.tags.iter().map(|t| lower(t)).collect();
        c.tags.iter().all(|t| have.contains(&lower(t)))
    };
    let os = c.os.is_empty()
        || f.os
            .as_deref()
            .is_some_and(|o| c.os.iter().any(|p| lower(o).starts_with(&lower(p))));
    ou && groups && host && net && tags && os
}

/// Whether the distinguished name `ou` is `want` or below it: equal, or
/// ending with `want` after a separating comma that is not escaped (RFC
/// 4514: a comma preceded by an odd number of backslashes is part of a
/// value, so `OU=A\,OU=B,...` is one OU named `A,OU=B`, not below `OU=B`).
/// Both are lowercase.
fn ou_within(ou: &str, want: &str) -> bool {
    if ou == want {
        return true;
    }
    let Some(head) = ou.strip_suffix(want) else {
        return false;
    };
    let Some(before) = head.strip_suffix(',') else {
        return false;
    };
    let slashes = before.bytes().rev().take_while(|b| *b == b'\\').count();
    slashes % 2 == 0
}

/// Longest hostname compared, in bytes (a DNS name is at most 253).
const MAX_HOSTNAME_BYTES: usize = 255;

/// `*` and `?` wildcard matching with two pointers and one backtrack
/// point: O(|pattern| × |text|) in the worst case, and no extra space.
/// Patterns are at most 2,048 bytes (validated) and hostnames at most
/// [`MAX_HOSTNAME_BYTES`] (longer ones never match), so the work is bounded.
fn wildcard(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// A network, as an address and a prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn contains(self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

fn parse_cidr(s: &str) -> Option<Cidr> {
    let (addr, prefix) = s.split_once('/')?;
    let addr: IpAddr = addr.parse().ok()?;
    if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) || prefix.len() > 3 {
        return None;
    }
    let prefix: u8 = prefix.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    (prefix <= max).then_some(Cidr { addr, prefix })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_escaped_comma_is_not_an_ou_boundary() {
        let within = |ou: &str, want: &str| ou_within(&ou.to_lowercase(), &want.to_lowercase());
        let trusted = "OU=Trusted,DC=example,DC=org";
        assert!(within("OU=Trusted,DC=example,DC=org", trusted));
        assert!(within("OU=Sales,OU=Trusted,DC=example,DC=org", trusted));
        assert!(!within("OU=Other\\,OU=Trusted,DC=example,DC=org", trusted));
        assert!(
            within("OU=Back\\\\,OU=Trusted,DC=example,DC=org", trusted),
            "an escaped backslash"
        );
        assert!(!within("OU=NotTrusted,DC=example,DC=org", trusted));
    }

    #[test]
    fn overlong_hostnames_never_match() {
        let c = PlacementConditions {
            hostname: vec!["*".to_owned()],
            ..PlacementConditions::default()
        };
        let f = PlacementFacts {
            hostname: Some("a".repeat(256)),
            ..PlacementFacts::default()
        };
        assert!(!matches(&c, &f));
    }

    #[test]
    fn wildcards_match_runs_and_single_characters() {
        assert!(wildcard("ws-*", "ws-001"));
        assert!(wildcard("ws-??1", "ws-001"));
        assert!(!wildcard("ws-??1", "ws-0011"));
        assert!(wildcard("*", ""));
        assert!(!wildcard("srv*", "ws-001"));
        assert!(wildcard("*-*-*", "a-b-c"));
    }

    #[test]
    fn cidrs_contain_addresses_of_their_family_only() {
        let n = parse_cidr("10.1.0.0/16").unwrap();
        assert!(n.contains("10.1.200.3".parse().unwrap()));
        assert!(!n.contains("10.2.0.1".parse().unwrap()));
        assert!(!n.contains("::1".parse().unwrap()));
        assert!(
            parse_cidr("0.0.0.0/0")
                .unwrap()
                .contains("192.0.2.1".parse().unwrap())
        );
        let v6 = parse_cidr("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8:1::5".parse().unwrap()));
        assert!(parse_cidr("10.0.0.0/33").is_none());
        assert!(parse_cidr("10.0.0.0/+8").is_none());
        assert!(parse_cidr("10.0.0.0").is_none());
    }

    #[test]
    fn every_set_condition_must_match_and_unknown_facts_never_do() {
        let c = PlacementConditions {
            directory_ou: vec!["OU=Laptops,DC=example,DC=org".to_owned()],
            hostname: vec!["LT-*".to_owned()],
            ..PlacementConditions::default()
        };
        let mut f = PlacementFacts {
            directory_ou: Some("ou=sales,OU=Laptops,DC=example,DC=org".to_owned()),
            hostname: Some("lt-0042".to_owned()),
            ..PlacementFacts::default()
        };
        assert!(matches(&c, &f));
        f.hostname = None;
        assert!(!matches(&c, &f));
        f.hostname = Some("lt-0042".to_owned());
        f.directory_ou = Some("OU=NotLaptops,DC=example,DC=org".to_owned());
        assert!(!matches(&c, &f));
        let tags = PlacementConditions {
            tags: vec!["Finance".to_owned(), "vdi".to_owned()],
            ..PlacementConditions::default()
        };
        let f = PlacementFacts {
            tags: vec!["finance".to_owned()],
            ..PlacementFacts::default()
        };
        assert!(!matches(&tags, &f), "every tag is required");
    }
}
