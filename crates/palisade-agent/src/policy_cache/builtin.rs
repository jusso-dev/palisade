//! The built-in policies the agent runs when no bundle loads (ADR 0018).
//!
//! - **First install**: no policy was ever accepted. Audit mode, so nothing
//!   is blocked before the first bundle arrives; every would-block decision
//!   is reported (`PolicyMissing`). The mandatory blocklists of #87 join it
//!   when the agent ships them.
//! - **Emergency**: a policy was accepted before, but neither `active` nor
//!   `previous` loads. Enforce mode, and every unknown object is blocked.
//!   #326 replaces the content with ADR 0018's emergency policy (allow
//!   OS-signed binaries and Palisade itself), and makes it audit-only in
//!   `native_only` mode. Until then it is stricter than that policy, never
//!   weaker.
//!
//! Neither has any rule, so both build without error; the tests check it.

use palisade_core::Uuid7;
use palisade_policy::{
    model::{
        GovernanceSettings, Metadata, Mode, ModeOptions, Policy, PolicyDocument, PolicyId,
        PolicySettings, PrecedenceModel, PrecedenceOptions, UnknownPolicy,
    },
    schema,
    validate::ValidatedPolicy,
};

/// Which built-in policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Builtin {
    /// No policy yet: audit mode.
    FirstInstall,
    /// Both cache files failed: enforce mode, block unknown.
    Emergency,
}

/// The policy IDs of the built-in policies: fixed UUIDv7s, so events name
/// them the same way on every device.
const FIRST_INSTALL_ID: [u8; 16] = [
    0x01, 0x9a, 0xc0, 0x00, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];
const EMERGENCY_ID: [u8; 16] = [
    0x01, 0x9a, 0xc0, 0x00, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
];

impl Builtin {
    /// The policy document.
    #[expect(
        clippy::expect_used,
        reason = "fixed UUIDv7s; `builtins_validate_and_build` tests them"
    )]
    pub fn document(self) -> PolicyDocument {
        let (id, name, mode) = match self {
            Self::FirstInstall => (
                FIRST_INSTALL_ID,
                "Built-in first-install policy",
                Mode::Audit,
            ),
            Self::Emergency => (EMERGENCY_ID, "Built-in emergency policy", Mode::Enforce),
        };
        PolicyDocument {
            schema_version: schema::CURRENT,
            policy: Policy {
                id: PolicyId(Uuid7::from_bytes(id).expect("a fixed UUIDv7")),
                name: name.to_owned(),
                description: None,
                revision: 1,
                precedence_model: PrecedenceModel::default(),
                precedence_options: PrecedenceOptions::default(),
                mode,
                mode_options: ModeOptions::default(),
                settings: PolicySettings::default(),
                // Blocks every unknown object, which audit mode reports
                // and enforce mode applies.
                unknown: UnknownPolicy::default(),
                governance: GovernanceSettings::default(),
                rule_sets: Vec::new(),
                scope: None,
                rule_set_scopes: Vec::new(),
                location_profiles: Vec::new(),
                // No catch-all allow, so nothing to confirm.
                confirm_permit_all: None,
                metadata: Metadata::default(),
            },
            rule_sets: Vec::new(),
        }
    }

    /// The validated policy.
    pub fn policy(self) -> ValidatedPolicy {
        #[expect(
            clippy::expect_used,
            reason = "a fixed document with no rules; `builtins_validate_and_build` tests it"
        )]
        self.document()
            .validate()
            .expect("the built-in policies are valid")
    }
}

#[cfg(test)]
mod tests {
    use palisade_policy::engine::{Engine, EngineConfig};

    use super::*;

    #[test]
    fn builtins_validate_and_build() {
        assert!(Uuid7::from_bytes(FIRST_INSTALL_ID).is_some());
        assert!(Uuid7::from_bytes(EMERGENCY_ID).is_some());
        for (builtin, mode) in [
            (Builtin::FirstInstall, Mode::Audit),
            (Builtin::Emergency, Mode::Enforce),
        ] {
            let policy = builtin.policy();
            assert_eq!(policy.document().policy.mode, mode);
            assert!(policy.document().rule_sets.is_empty());
            Engine::new(policy, EngineConfig::default()).unwrap();
        }
        assert_ne!(
            Builtin::FirstInstall.document().policy.id,
            Builtin::Emergency.document().policy.id
        );
    }
}
