//! Where a policy sets its enforcement modes (#36).
//!
//! The policy's `mode` is the base. [`ModeOptions`] adds the modes that
//! apply per object type and while the device is disconnected, and each
//! rule set may carry a `mode_override`. How these combine into the
//! effective mode of one decision is [`crate::mode`].

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::settings::unique_keys;
use super::{Mode, ObjectType};

/// Limits on the mode options, used by the schema and validation.
pub mod limits {
    /// Shortest `disconnected_after_secs`, in seconds.
    pub const DISCONNECTED_AFTER_MIN: u32 = 60;
    /// Longest `disconnected_after_secs`, in seconds (30 days).
    pub const DISCONNECTED_AFTER_MAX: u32 = 2_592_000;
    /// The default `disconnected_after_secs` is this many check-in
    /// intervals.
    pub const DISCONNECTED_AFTER_POLLS: u32 = 3;
}

use limits::{DISCONNECTED_AFTER_MAX, DISCONNECTED_AFTER_MIN, DISCONNECTED_AFTER_POLLS};

/// Mode settings besides the base `mode`. Each is optional in a document.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModeOptions {
    /// The mode per object type, replacing the base mode for that type:
    /// for example `script.powershell: audit` while everything else is
    /// enforced. `disabled` is not allowed here: only a whole device can
    /// be disabled.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(deserialize_with = "unique_keys")]
    #[schemars(transform = object_type_keys)]
    pub mode_by_type: BTreeMap<ObjectType, Mode>,
    /// The base mode while the device is disconnected: `mode` itself or a
    /// stricter mode, so losing the server never relaxes a device. It also
    /// raises a weaker `mode_by_type`. Unset means the same as `mode`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode_disconnected: Option<Mode>,
    /// How long after its last successful check-in a device counts as
    /// disconnected, in seconds: 60 to 2592000, and at least the check-in
    /// interval. Unset means three check-in intervals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = DISCONNECTED_AFTER_MIN, max = DISCONNECTED_AFTER_MAX))]
    pub disconnected_after_secs: Option<u32>,
}

impl ModeOptions {
    /// Whether every option has its default.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    /// How long after its last check-in a device counts as disconnected,
    /// in seconds, with the default applied for a check-in interval of
    /// `poll_interval_secs`.
    #[must_use]
    pub fn disconnected_after(&self, poll_interval_secs: u32) -> u64 {
        self.disconnected_after_secs.map_or_else(
            || u64::from(poll_interval_secs) * u64::from(DISCONNECTED_AFTER_POLLS),
            u64::from,
        )
    }
}

/// The schema of `mode_by_type` keys: the object type names.
fn object_type_keys(schema: &mut schemars::Schema) {
    let names: Vec<String> = ObjectType::ALL.iter().map(ToString::to_string).collect();
    schema.insert(
        "propertyNames".to_owned(),
        serde_json::json!({ "enum": names }),
    );
}
