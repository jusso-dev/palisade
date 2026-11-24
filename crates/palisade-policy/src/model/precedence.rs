//! The options of a policy's precedence model (#35).
//!
//! [`PrecedenceModel`](super::PrecedenceModel) chooses how the matching
//! rules of the ordinary rule sets are combined. [`PrecedenceOptions`] holds
//! the settings that tune each model. Every option has a default, and an
//! option that the selected model does not use is ignored, with the warning
//! `precedence_option_unused`. The semantics are in [`crate::precedence`].

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Settings of the precedence models. Each is optional in a document.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrecedenceOptions {
    /// Which allow decides when several allow rules of different kinds
    /// could (`deny_wins`, `allow_wins` and `specificity`). The default,
    /// `most_restrictive`, ranks `allow_contained` over `allow` over
    /// `allow_elevated`.
    #[serde(default, skip_serializing_if = "AllowTiebreak::is_default")]
    pub allow_tiebreak: AllowTiebreak,
    /// `allow_wins` only: within one rule set, a rule with a more specific
    /// identity beats a less specific one before allow-over-deny applies,
    /// so a denied file in an allowed folder stays denied. Off by default.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub granularity_tiebreak: bool,
    /// `first_match` only: rules of curated (read-only) rule sets are
    /// evaluated before every custom rule, whatever their `order`. On by
    /// default.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub curated_first: bool,
    /// `specificity` only: which action wins between rules of the same
    /// specificity. `deny` by default.
    #[serde(default, skip_serializing_if = "TierTiebreak::is_default")]
    pub same_tier_tiebreak: TierTiebreak,
    /// `priority` only: whether the lowest or the highest `priority`
    /// number wins. `lower_wins` by default.
    #[serde(default, skip_serializing_if = "PriorityDirection::is_default")]
    pub priority_direction: PriorityDirection,
}

impl Default for PrecedenceOptions {
    fn default() -> Self {
        Self {
            allow_tiebreak: AllowTiebreak::default(),
            granularity_tiebreak: false,
            curated_first: true,
            same_tier_tiebreak: TierTiebreak::default(),
            priority_direction: PriorityDirection::default(),
        }
    }
}

impl PrecedenceOptions {
    /// Whether every option has its default.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

const fn default_true() -> bool {
    true
}

/// serde's `skip_serializing_if` passes a reference.
const fn is_true(b: &bool) -> bool {
    *b
}

/// Which allow decides among allows of different kinds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AllowTiebreak {
    /// `allow_contained`, then `allow`, then `allow_elevated` (with
    /// `condition: always` before `if_required`). The default.
    #[default]
    MostRestrictive,
    /// The reverse: `allow_elevated` (`if_required` before `always`), then
    /// `allow`, then `allow_contained`.
    MostPermissive,
}

impl AllowTiebreak {
    const fn is_default(&self) -> bool {
        matches!(self, Self::MostRestrictive)
    }
}

/// Which action wins between rules of the same specificity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TierTiebreak {
    /// A deny beats an allow. The default.
    #[default]
    Deny,
    /// An allow beats a deny.
    Allow,
}

impl TierTiebreak {
    const fn is_default(&self) -> bool {
        matches!(self, Self::Deny)
    }
}

/// Which `priority` number wins.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PriorityDirection {
    /// The lowest number wins. The default.
    #[default]
    LowerWins,
    /// The highest number wins.
    HigherWins,
}

impl PriorityDirection {
    const fn is_default(&self) -> bool {
        matches!(self, Self::LowerWins)
    }
}
