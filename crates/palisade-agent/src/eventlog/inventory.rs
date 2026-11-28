//! The per-device table of active OS-native policies (#58).
//!
//! Each policy activation event (3099) names a policy (its ID, name, GUID
//! and hash) and its option bits. The table keeps the latest activation of
//! each policy, so health (#67) can report which OS-native policies are
//! active and the server can check its deployed policies against it (#6).
//! Periodic reads of the policy store (the OS policy tool's JSON list, or
//! the active policy directory) will reconcile it; they come with the E06
//! policy parser.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use palisade_core::codeintegrity::PolicyOptions;
use palisade_proto::events::Timestamp;
use palisade_proto::mapping::Record;

/// The policy activation event ID.
pub const POLICY_ACTIVATED: u32 = 3099;

/// The most policies the table keeps. The OS allows far fewer active at
/// once; the cap bounds memory against a forged flood.
pub const MAX_POLICIES: usize = 256;

/// One active policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivePolicy {
    /// The policy's ID string, or its GUID where no ID is given.
    pub id: String,
    /// The policy's name.
    pub name: Option<String>,
    /// The policy's GUID.
    pub guid: Option<String>,
    /// The policy's hash, as hex.
    pub hash: Option<String>,
    /// The option bits, if they could be read.
    pub options: Option<PolicyOptions>,
    /// When it was activated.
    pub activated: Timestamp,
}

impl ActivePolicy {
    /// The names of its set option bits.
    #[must_use]
    pub fn option_names(&self) -> Vec<&'static str> {
        self.options
            .map(|o| o.names().collect())
            .unwrap_or_default()
    }

    /// Whether it is in audit mode. `None` when the options are unknown.
    #[must_use]
    pub fn is_audit(&self) -> Option<bool> {
        self.options.map(PolicyOptions::is_audit)
    }
}

/// The table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyInventory {
    policies: BTreeMap<String, ActivePolicy>,
    refused: u64,
}

fn field<'a>(r: &'a Record, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .find_map(|n| r.fields.get(*n))
        .map(|v| v.trim())
        .filter(|v| !v.is_empty() && *v != "-")
}

/// Reads an options value: decimal, or hex with `0x`.
fn options(text: &str) -> Option<PolicyOptions> {
    let n = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
        None => text.parse().ok()?,
    };
    Some(PolicyOptions(n))
}

impl PolicyInventory {
    /// Records `record` if it is a policy activation. Returns whether the
    /// table changed.
    pub fn observe(&mut self, record: &Record) -> bool {
        if record.event_id != POLICY_ACTIVATED {
            return false;
        }
        let guid = field(record, &["PolicyGUID"]).map(str::to_owned);
        let Some(id) = field(record, &["PolicyIdBuffer", "PolicyID"])
            .map(str::to_owned)
            .or_else(|| guid.clone())
        else {
            self.refused = self.refused.saturating_add(1);
            return false;
        };
        if !self.policies.contains_key(&id) && self.policies.len() >= MAX_POLICIES {
            self.refused = self.refused.saturating_add(1);
            return false;
        }
        let policy = ActivePolicy {
            id: id.clone(),
            name: field(record, &["PolicyNameBuffer", "PolicyName"]).map(str::to_owned),
            guid,
            hash: field(record, &["PolicyHash"]).map(str::to_owned),
            options: field(record, &["Options"]).and_then(options),
            activated: record.time_created,
        };
        // An older activation delivered late does not replace a newer one.
        if self
            .policies
            .get(&id)
            .is_some_and(|p| p.activated > policy.activated)
        {
            return false;
        }
        self.policies.insert(id, policy).is_none_or(|_| true)
    }

    /// The active policies, by ID.
    pub fn policies(&self) -> impl Iterator<Item = &ActivePolicy> {
        self.policies.values()
    }

    /// How many activations could not be recorded (no ID, or the table was
    /// full).
    #[must_use]
    pub const fn refused(&self) -> u64 {
        self.refused
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: u32, at: i64, fields: &[(&str, &str)]) -> Record {
        Record {
            event_id: id,
            time_created: Timestamp::from_unix_micros(at).unwrap(),
            record_id: None,
            channel: None,
            activity_id: None,
            fields: fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    #[test]
    fn activations_are_kept_by_policy() {
        let mut inv = PolicyInventory::default();
        assert!(!inv.observe(&rec(3076, 0, &[])));
        let a = rec(
            3099,
            10,
            &[
                ("PolicyIdBuffer", "Base"),
                ("PolicyNameBuffer", "Base policy"),
                ("PolicyGUID", "{a244370e-44c9-4c06-b551-f6016e563076}"),
                ("PolicyHash", "AB"),
                ("Options", "0x00010004"),
            ],
        );
        assert!(inv.observe(&a));
        let p = inv.policies().next().unwrap();
        assert_eq!(p.option_names(), ["UMCI", "Audit"]);
        assert_eq!(p.is_audit(), Some(true));
        assert_eq!(p.name.as_deref(), Some("Base policy"));
        // A later activation replaces it; an older one does not.
        let newer = rec(3099, 20, &[("PolicyIdBuffer", "Base"), ("Options", "4")]);
        assert!(inv.observe(&newer));
        assert_eq!(inv.policies().next().unwrap().is_audit(), Some(false));
        assert!(!inv.observe(&a));
        // An unreadable options value is unknown, not zero.
        inv.observe(&rec(3099, 30, &[("PolicyGUID", "{g}"), ("Options", "zz")]));
        let g = inv.policies().find(|p| p.id == "{g}").unwrap();
        assert_eq!(g.is_audit(), None);
        assert!(g.option_names().is_empty());
        assert!(options("0Xff").is_some());
    }

    #[test]
    fn unidentified_and_excess_activations_are_refused() {
        let mut inv = PolicyInventory::default();
        assert!(!inv.observe(&rec(3099, 0, &[("PolicyIdBuffer", "-")])));
        for i in 0..MAX_POLICIES {
            inv.observe(&rec(3099, 0, &[("PolicyID", &i.to_string())]));
        }
        assert!(!inv.observe(&rec(3099, 0, &[("PolicyID", "new")])));
        assert_eq!(inv.refused(), 2);
        assert_eq!(inv.policies().count(), MAX_POLICIES);
    }
}
