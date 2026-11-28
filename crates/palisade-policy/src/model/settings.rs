//! Typed policy settings.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::ScriptKind;

/// Allowed ranges of the numeric settings, used by both the schema and
/// validation.
pub mod ranges {
    /// Shortest check-in interval, in seconds.
    pub const POLL_INTERVAL_MIN: u32 = 60;
    /// Longest check-in interval, in seconds (seven days).
    pub const POLL_INTERVAL_MAX: u32 = 604_800;
    /// Longest decision cache lifetime, in seconds (one day).
    pub const DECISION_CACHE_TTL_MAX: u32 = 86_400;
    /// Most override duration slots.
    pub const OVERRIDE_SLOTS_MAX: usize = 5;
    /// Longest override duration, in minutes (seven days).
    pub const OVERRIDE_MINUTES_MAX: u32 = 10_080;
    /// Smallest process ancestry depth.
    pub const ANCESTOR_DEPTH_MIN: u8 = 1;
    /// Largest process ancestry depth.
    pub const ANCESTOR_DEPTH_MAX: u8 = 16;
    /// Most entries in `advanced`.
    pub const ADVANCED_KEYS_MAX: usize = 256;
    /// Shortest `group_cache_max_age_secs` (one hour).
    pub const GROUP_CACHE_MAX_AGE_MIN: u32 = 3_600;
    /// Longest `group_cache_max_age_secs`, and the default (one day).
    pub const GROUP_CACHE_MAX_AGE_MAX: u32 = 86_400;
    /// Most criteria per rule a policy may allow, and the default: the
    /// fixed maximum ([`MAX_CRITERIA_PER_RULE`](crate::model::limits::MAX_CRITERIA_PER_RULE)).
    pub const CRITERIA_PER_RULE_MAX: u8 = 32;
    /// Deepest tree a policy may allow, and the default: the fixed maximum
    /// ([`MAX_TREE_DEPTH`](crate::model::limits::MAX_TREE_DEPTH)).
    pub const TREE_DEPTH_MAX: u8 = 8;
    /// Most values per criterion a policy may allow, and the default: the
    /// fixed maximum ([`MAX_VALUES_PER_CRITERION`](crate::model::limits::MAX_VALUES_PER_CRITERION)).
    pub const VALUES_PER_CRITERION_MAX: u8 = 25;
    /// Shortest per-rule budget for warm and cold criteria, in
    /// milliseconds.
    pub const CONDITION_BUDGET_MIN: u16 = 1;
    /// Longest per-rule budget, in milliseconds (ten seconds).
    pub const CONDITION_BUDGET_MAX: u16 = 10_000;
    /// The default per-rule budget, in milliseconds.
    pub const CONDITION_BUDGET_DEFAULT: u16 = 50;
}

use ranges::{
    ADVANCED_KEYS_MAX, ANCESTOR_DEPTH_MAX, ANCESTOR_DEPTH_MIN, CONDITION_BUDGET_DEFAULT,
    CONDITION_BUDGET_MAX, CONDITION_BUDGET_MIN, CRITERIA_PER_RULE_MAX, DECISION_CACHE_TTL_MAX,
    GROUP_CACHE_MAX_AGE_MAX, GROUP_CACHE_MAX_AGE_MIN, OVERRIDE_MINUTES_MAX, OVERRIDE_SLOTS_MAX,
    POLL_INTERVAL_MAX, POLL_INTERVAL_MIN, TREE_DEPTH_MAX, VALUES_PER_CRITERION_MAX,
};

/// Settings that apply to the whole policy. Every field is optional in a
/// document and has the default shown in the schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct PolicySettings {
    /// Control level for scripts of a kind not listed in `script_control_by_kind`.
    pub script_control: ControlLevel,
    /// Control level per script kind, overriding `script_control`.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(deserialize_with = "unique_keys")]
    #[schemars(transform = script_kind_keys)]
    pub script_control_by_kind: BTreeMap<ScriptKind, ControlLevel>,
    /// Control level for libraries.
    pub dll_control: ControlLevel,
    /// Control level for drivers.
    pub driver_control: ControlLevel,
    /// Whether the agent records process command lines. Off by default for
    /// privacy (#18).
    pub capture_command_line: bool,
    /// Agent check-in interval, in seconds.
    #[schemars(range(min = POLL_INTERVAL_MIN, max = POLL_INTERVAL_MAX))]
    pub poll_interval_secs: u32,
    /// How long a decision may be cached, in seconds. `0` disables the cache.
    #[schemars(range(max = DECISION_CACHE_TTL_MAX))]
    pub decision_cache_ttl_secs: u32,
    /// Durations, in minutes, offered for override sessions (#9). At most 5
    /// slots, each at most 10080. `0` marks a disabled slot.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = OVERRIDE_SLOTS_MAX), inner(range(max = OVERRIDE_MINUTES_MAX)))]
    pub override_durations: Vec<u32>,
    /// Which clock schedules use, unless a schedule sets its own (#38).
    pub time_zone_basis: TimeZoneBasis,
    /// How old cached group memberships that are not in the token
    /// (cloud-directory groups) may be before scopes treat them as unknown,
    /// in seconds (#38). From 3600 to 86400.
    #[schemars(range(min = GROUP_CACHE_MAX_AGE_MIN, max = GROUP_CACHE_MAX_AGE_MAX))]
    pub group_cache_max_age_secs: u32,
    /// How many ancestors process criteria may inspect (#31).
    #[schemars(range(min = ANCESTOR_DEPTH_MIN, max = ANCESTOR_DEPTH_MAX))]
    pub max_ancestor_depth: u8,
    /// Most criteria in one rule's match tree (#33): 1 to 32, the fixed
    /// maximum and the default. A policy can tighten the limit, never
    /// raise it.
    #[schemars(range(min = 1, max = CRITERIA_PER_RULE_MAX))]
    #[serde(skip_serializing_if = "is_max_criteria_per_rule_default")]
    pub max_criteria_per_rule: u8,
    /// Deepest match tree (#33), where a single criterion has depth 1: 1 to
    /// 8, the fixed maximum and the default.
    #[schemars(range(min = 1, max = TREE_DEPTH_MAX))]
    #[serde(skip_serializing_if = "is_max_tree_depth_default")]
    pub max_tree_depth: u8,
    /// Most values in one criterion (#33): 1 to 25, the fixed maximum and
    /// the default.
    #[schemars(range(min = 1, max = VALUES_PER_CRITERION_MAX))]
    #[serde(skip_serializing_if = "is_max_values_per_criterion_default")]
    pub max_values_per_criterion: u8,
    /// The most time, in milliseconds, the agent spends collecting the
    /// warm and cold facts of one rule (#33, #329): 1 to 10000, default
    /// 50. A fact not collected in time is unknown, with the trace note
    /// `condition_timeout`. Separate from the per-decision watchdog (#42).
    #[schemars(range(min = CONDITION_BUDGET_MIN, max = CONDITION_BUDGET_MAX))]
    #[serde(skip_serializing_if = "is_condition_budget_default")]
    pub condition_budget_ms: u16,
    /// Engineering settings, checked against a registry of known keys. The
    /// registry is empty in this version, so any key is rejected unless
    /// `allow_unknown_advanced` is set. Keys are added only with the feature
    /// that reads them (#330), and never relax a decision.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(deserialize_with = "unique_keys")]
    #[schemars(transform = advanced_keys)]
    pub advanced: BTreeMap<String, AdvancedValue>,
    /// Accept keys in `advanced` that the registry does not know.
    pub allow_unknown_advanced: bool,
}

/// Most bytes in an `advanced` key.
pub const ADVANCED_KEY_MAX_BYTES: usize = 128;

/// The schema of `advanced` keys: printable ASCII identifiers. Validation
/// checks the same rule ([`is_valid_advanced_key`]).
pub const ADVANCED_KEY_PATTERN: &str = "^[a-z][a-z0-9_.-]{0,127}$";

/// Whether `key` is a well-formed `advanced` key: a lowercase ASCII letter,
/// then up to 127 lowercase letters, digits, `_`, `.` or `-`.
#[must_use]
pub fn is_valid_advanced_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && key.len() <= ADVANCED_KEY_MAX_BYTES
        && bytes.all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
        })
}

/// Reads a map and rejects repeated keys. serde's own map reader keeps the
/// last value, which would let two tools disagree about one document.
pub(crate) fn unique_keys<'de, D, K, V>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    K: Deserialize<'de> + Ord + core::fmt::Debug,
    V: Deserialize<'de>,
{
    struct Visitor<K, V>(core::marker::PhantomData<(K, V)>);
    impl<'de, K, V> serde::de::Visitor<'de> for Visitor<K, V>
    where
        K: Deserialize<'de> + Ord + core::fmt::Debug,
        V: Deserialize<'de>,
    {
        type Value = BTreeMap<K, V>;
        fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("a map with unique keys")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut out = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<K, V>()? {
                if out.contains_key(&key) {
                    return Err(serde::de::Error::custom(format_args!(
                        "duplicate key {key:?}"
                    )));
                }
                out.insert(key, value);
            }
            Ok(out)
        }
    }
    deserializer.deserialize_map(Visitor(core::marker::PhantomData))
}

// schemars describes a map's values but not its keys, and its `length`
// attribute does not apply to maps, so these add the missing constraints.

fn script_kind_keys(schema: &mut schemars::Schema) {
    let names: Vec<&str> = ScriptKind::ALL.iter().map(|k| k.as_str()).collect();
    schema.insert(
        "propertyNames".to_owned(),
        serde_json::json!({ "enum": names }),
    );
}

fn advanced_keys(schema: &mut schemars::Schema) {
    schema.insert("maxProperties".to_owned(), ADVANCED_KEYS_MAX.into());
    schema.insert(
        "propertyNames".to_owned(),
        serde_json::json!({ "pattern": ADVANCED_KEY_PATTERN }),
    );
}

impl Default for PolicySettings {
    fn default() -> Self {
        Self {
            script_control: ControlLevel::Enforce,
            script_control_by_kind: BTreeMap::new(),
            dll_control: ControlLevel::Enforce,
            driver_control: ControlLevel::Enforce,
            capture_command_line: false,
            poll_interval_secs: 900,
            decision_cache_ttl_secs: 300,
            override_durations: Vec::new(),
            time_zone_basis: TimeZoneBasis::DeviceLocal,
            group_cache_max_age_secs: GROUP_CACHE_MAX_AGE_MAX,
            max_ancestor_depth: 8,
            max_criteria_per_rule: CRITERIA_PER_RULE_MAX,
            max_tree_depth: TREE_DEPTH_MAX,
            max_values_per_criterion: VALUES_PER_CRITERION_MAX,
            condition_budget_ms: CONDITION_BUDGET_DEFAULT,
            advanced: BTreeMap::new(),
            allow_unknown_advanced: false,
        }
    }
}

/// Whether a class of object is controlled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ControlLevel {
    /// Not evaluated.
    Off,
    /// Evaluated, and would-block decisions are reported only.
    Audit,
    /// Evaluated and enforced.
    Enforce,
}

/// The clock that schedules are interpreted in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TimeZoneBasis {
    /// The device's local time zone.
    DeviceLocal,
    /// Coordinated Universal Time.
    Utc,
    /// The time zone of the session's user, if the agent can read it, and
    /// otherwise the device's (#38).
    UserLocal,
}

/// A scalar value in `advanced`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum AdvancedValue {
    /// A boolean.
    Bool(bool),
    /// A signed integer.
    Int(i64),
    /// A string of at most 2048 bytes, with no control characters.
    Text(#[schemars(length(max = 2048))] String),
}

/// serde's `skip_serializing_if` passes a reference.
#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_max_criteria_per_rule_default(v: &u8) -> bool {
    *v == CRITERIA_PER_RULE_MAX
}

/// serde's `skip_serializing_if` passes a reference.
#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_max_tree_depth_default(v: &u8) -> bool {
    *v == TREE_DEPTH_MAX
}

/// serde's `skip_serializing_if` passes a reference.
#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_max_values_per_criterion_default(v: &u8) -> bool {
    *v == VALUES_PER_CRITERION_MAX
}

/// serde's `skip_serializing_if` passes a reference.
#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_condition_budget_default(v: &u16) -> bool {
    *v == CONDITION_BUDGET_DEFAULT
}
