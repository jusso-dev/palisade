//! The policy enforcement mode.

/// How a policy's decisions take effect (#36).
///
/// The variants are declared from weakest to strongest, so the derived
/// ordering ranks them. The "strictest" merge in #36 treats `learning` and
/// `audit` as equally strong; that rule belongs to the merge code, not to this
/// ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum Mode {
    /// The engine is not consulted. The device is reported as unprotected.
    Disabled,
    /// Evaluate fully, allow everything, and report would-block decisions.
    Monitor,
    /// Like `monitor`, with a full event for every decision.
    Audit,
    /// Audit, and report every would-block object as a learning candidate.
    Learning,
    /// Decisions take effect: blocked means blocked.
    Enforce,
}
