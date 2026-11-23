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
}

use ranges::{
    ADVANCED_KEYS_MAX, ANCESTOR_DEPTH_MAX, ANCESTOR_DEPTH_MIN, DECISION_CACHE_TTL_MAX,
    OVERRIDE_MINUTES_MAX, OVERRIDE_SLOTS_MAX, POLL_INTERVAL_MAX, POLL_INTERVAL_MIN,
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
    /// Which clock schedules use.
    pub time_zone_basis: TimeZoneBasis,
    /// How many ancestors process criteria may inspect (#31).
    #[schemars(range(min = ANCESTOR_DEPTH_MIN, max = ANCESTOR_DEPTH_MAX))]
    pub max_ancestor_depth: u8,
    /// Engineering settings, checked against a registry of known keys. The
    /// registry is empty in this version, so any key is rejected unless
    /// `allow_unknown_advanced` is set.
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
fn unique_keys<'de, D, K, V>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
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
            max_ancestor_depth: 8,
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
