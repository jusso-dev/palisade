//! Policy bundle integrity decisions (part of #225): the anti-rollback
//! record, the signature mode, and which bundle the agent runs.
//!
//! This module is pure: no storage, no OS calls, no clock reads. The agent
//! (#61 policy cache, #220 tamper protection) supplies the bytes it read and
//! the time, and carries out what the functions here decide. The decisions
//! see only [`BundleMeta`] (tenant, target, `policy_version` and content
//! SHA-256) and the result of the envelope checks ([`Examined`]), which
//! [`envelope::verify`] produces from the bundle header (#43) and the
//! agent's trust set.
//!
//! - [`record`]: the anti-rollback record. It holds the **floor** (the
//!   highest version made `active` for a target) and the **fallback** (the
//!   version in `previous` that `active` directly replaced). Each copy is
//!   sealed with HMAC-SHA-256, and [`record::RecordCopies`] applies the
//!   copy-mismatch rule.
//! - [`SignatureMode`]: `audit`, `warn` or `enforce`, and the rule that
//!   relaxed modes need a dev build or an explicit group opt-in.
//! - [`select`]: what to run at startup (`active`, then `previous` under the
//!   one-step exception, then the emergency policy, then first-install
//!   audit) and whether a new `pending` bundle is accepted, following the
//!   failure table of ADR 0018 (which supersedes ADR 0012) and the activation
//!   order of ADR 0007.
//! - [`stale`]: staleness, which is reported but never changes what runs.
//! - [`envelope`]: the signed bundle envelope (#325): signing, and the
//!   verification that produces [`Examined`].
//!
//! Every rejection maps to exactly one event type ([`Rejection::event_type`],
//! [`select::Finding::event_type`]). None of these functions can return an
//! allow-all outcome: the only non-enforcing result is
//! [`select::Load::FirstInstall`], and it is returned only when the device has
//! never accepted a policy.

#![forbid(unsafe_code)]

pub mod envelope;
pub mod record;
pub mod select;
pub mod stale;

#[cfg(test)]
mod tests;

use std::fmt;

use palisade_core::Uuid7;

use crate::events::{EventType, HostId, Sha256Hex, TenantId};
use crate::pki::crypto;

/// What a bundle is for: a group, or one device, within a tenant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Target {
    /// The tenant.
    pub tenant: TenantId,
    /// The group or device.
    pub scope: Scope,
}

/// The group or device a bundle targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// Every device in a group.
    Group(Uuid7),
    /// One device.
    Device(HostId),
}

/// The facts about a bundle that the decisions need, which
/// [`envelope::verify`] reads from the bundle header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BundleMeta {
    /// The tenant and target named in the envelope.
    pub target: Target,
    /// `policy_version`: monotonic per target, starting at 1.
    pub version: u64,
    /// SHA-256 of the canonical bundle bytes ([`content_hash`]).
    pub sha256: Sha256Hex,
}

/// SHA-256 of the canonical bundle bytes, for [`BundleMeta::sha256`] and for
/// the periodic in-memory re-check (#225).
#[must_use]
pub fn content_hash(bundle: &[u8]) -> Sha256Hex {
    Sha256Hex::from_bytes(crypto::sha256(bundle))
}

/// The result of the envelope checks on one bundle file, before this
/// module decides anything (#225 check order, steps 1, 2, 5 and 6), as
/// [`envelope::verify`] returns it. Steps 3 (target) and 4 (version) are
/// applied here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Examined {
    /// Step 1 failed: the envelope is over the size limit, does not parse,
    /// or its bytes do not match the recorded hash. Never loadable, in any
    /// signature mode.
    Unreadable,
    /// The envelope parsed.
    Parsed {
        /// The envelope's metadata. Only trustworthy when `signature_valid`.
        meta: BundleMeta,
        /// Step 2: at least one signature from an active trusted
        /// `policy-signing` key verifies.
        signature_valid: bool,
        /// Step 5: `min_agent_version` is at or below this agent's version.
        agent_supported: bool,
        /// Step 6: the bundle schema validates (#43). Validate the body only
        /// after the signature verifies, or when the effective mode
        /// tolerates an invalid signature; otherwise pass `false`, because
        /// the signature check rejects it first.
        schema_supported: bool,
    },
}

/// Why a bundle was refused. Each maps to exactly one event type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rejection {
    /// The envelope could not be read (step 1). Reported as
    /// `policy.signature.invalid`, because the bundle cannot be
    /// authenticated.
    Unreadable,
    /// No valid trusted signature (step 2), in `enforce` mode.
    SignatureInvalid,
    /// The tenant or target is not this device's (step 3).
    TargetMismatch,
    /// The version is below the anti-rollback floor or the current bundle,
    /// or is 0 (step 4).
    Rollback,
    /// The version equals the current bundle's but the content differs.
    /// The server never reuses a version, so this is treated as a replay.
    VersionReused,
    /// `min_agent_version` is above this agent's (step 5). Reported as
    /// `policy.schema_unsupported`, which prompts the same agent upgrade.
    AgentTooOld,
    /// The bundle schema is unknown or newer (step 6).
    SchemaUnsupported,
}

impl Rejection {
    /// The event this rejection raises.
    #[must_use]
    pub const fn event_type(self) -> EventType {
        match self {
            Self::Unreadable | Self::SignatureInvalid => EventType::PolicySignatureInvalid,
            Self::TargetMismatch => EventType::PolicyTargetMismatch,
            Self::Rollback | Self::VersionReused => EventType::PolicyRollbackRejected,
            Self::AgentTooOld | Self::SchemaUnsupported => EventType::PolicySchemaUnsupported,
        }
    }
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unreadable => "the bundle envelope cannot be read",
            Self::SignatureInvalid => "no valid signature from a trusted policy-signing key",
            Self::TargetMismatch => "the bundle is for another tenant or target",
            Self::Rollback => "the bundle version is below the accepted version",
            Self::VersionReused => "the bundle reuses the current version with other content",
            Self::AgentTooOld => "the bundle needs a newer agent",
            Self::SchemaUnsupported => "the bundle schema is not supported",
        })
    }
}

impl std::error::Error for Rejection {}

/// `policy.signature_mode` (#225).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum SignatureMode {
    /// Load bundles whose signature is invalid, and raise
    /// `policy.signature.invalid`.
    Audit,
    /// As `audit`, plus a tray notification.
    Warn,
    /// Refuse them and keep the last known good policy. The default.
    #[default]
    Enforce,
}

/// Where a relaxed signature mode may come from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ModeGate {
    /// This is a dev build of the agent.
    pub dev_build: bool,
    /// The device's group explicitly allows a relaxed mode. Take this only
    /// from a bundle whose signature verified, so that an unsigned bundle
    /// can never relax the check that would refuse it.
    pub group_opt_in: bool,
}

/// The signature mode in force, after the gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EffectiveMode {
    mode: SignatureMode,
}

impl EffectiveMode {
    /// `enforce`.
    pub const ENFORCE: Self = Self {
        mode: SignatureMode::Enforce,
    };

    /// The mode in force: `requested` if it is `enforce` or the gate allows
    /// a relaxed mode, otherwise `enforce`.
    #[must_use]
    pub const fn resolve(requested: SignatureMode, gate: ModeGate) -> Self {
        let allowed = gate.dev_build || gate.group_opt_in;
        Self {
            mode: if allowed {
                requested
            } else {
                SignatureMode::Enforce
            },
        }
    }

    /// The mode.
    #[must_use]
    pub const fn mode(self) -> SignatureMode {
        self.mode
    }

    /// Whether a bundle with an invalid signature may load.
    #[must_use]
    pub const fn tolerates_invalid_signature(self) -> bool {
        !matches!(self.mode, SignatureMode::Enforce)
    }

    /// Whether the console shows its warning banner for this device.
    #[must_use]
    pub const fn console_banner(self) -> bool {
        self.tolerates_invalid_signature()
    }

    /// Whether loading a bundle with an invalid signature also notifies the
    /// user in the tray.
    #[must_use]
    pub const fn tray_notification(self) -> bool {
        matches!(self.mode, SignatureMode::Warn)
    }
}

impl Default for EffectiveMode {
    fn default() -> Self {
        Self::ENFORCE
    }
}

/// How a bundle passed the checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Passed {
    /// Every check passed.
    Verified(BundleMeta),
    /// Every check except the signature passed, and the mode tolerates that.
    /// Such a bundle never moves the floor, never becomes a fallback, and is
    /// never copied to `previous`.
    Unsigned(BundleMeta),
}

impl Passed {
    pub(crate) const fn meta(self) -> BundleMeta {
        match self {
            Self::Verified(m) | Self::Unsigned(m) => m,
        }
    }
}

/// Steps 1, 2, 3, 5 and 6 in #225's order. The version (step 4) depends on
/// the caller's state, so callers check it.
pub(crate) fn check(
    examined: Examined,
    expected: Target,
    mode: EffectiveMode,
) -> Result<Passed, Rejection> {
    let Examined::Parsed {
        meta,
        signature_valid,
        agent_supported,
        schema_supported,
    } = examined
    else {
        return Err(Rejection::Unreadable);
    };
    if !signature_valid && !mode.tolerates_invalid_signature() {
        return Err(Rejection::SignatureInvalid);
    }
    if meta.target != expected {
        return Err(Rejection::TargetMismatch);
    }
    if meta.version == 0 {
        return Err(Rejection::Rollback);
    }
    if !agent_supported {
        return Err(Rejection::AgentTooOld);
    }
    if !schema_supported {
        return Err(Rejection::SchemaUnsupported);
    }
    Ok(if signature_valid {
        Passed::Verified(meta)
    } else {
        Passed::Unsigned(meta)
    })
}
