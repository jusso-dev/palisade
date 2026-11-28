//! The built-in policies the agent runs when no bundle loads (ADR 0018).
//!
//! - **First install**: no policy was ever accepted. Audit mode, so nothing
//!   is blocked before the first bundle arrives; every would-block decision
//!   is reported (`PolicyMissing`). The mandatory blocklists of #87 join it
//!   when the agent ships them.
//! - **Emergency**: a policy was accepted before, but neither `active` nor
//!   `previous` loads (#225, ADR 0018). It allows only:
//!   - binaries signed by the operating system's publishers, in the
//!     protected OS locations, through the agent's `system_baseline`
//!     ([`palisade_policy::unknown::baseline`]). That is narrower than "every
//!     OS-signed binary": user-writable folders inside the Windows directory
//!     and binaries outside the OS locations stay blocked;
//!   - Palisade's own images, each pinned by SHA-256 **and** publisher
//!     ([`SelfPin`]), so a copy signed by someone else or a re-signed file
//!     with other content is not allowed;
//!
//!   and blocks everything else. It runs in enforce mode where a Palisade
//!   enforcer exists, and in audit mode under the `native_only` strategy,
//!   where nothing in Palisade's layer enforces it ([`Enforcement`]). It is
//!   only ever applied to Palisade's own decisions: it never touches the
//!   installed OS-native policies (ADR 0018, "Emergency policy and the
//!   native layer").
//!
//! Every input that does not build (an invalid pin, baseline facts that do
//! not fit) is left out, which only removes an allow: the emergency policy
//! is never weaker than "block everything", and with no facts at all it is
//! exactly that. The tests check every combination builds.

use palisade_core::{RuleId, RuleSetId, Uuid7};
use palisade_policy::{
    model::{
        Action, Criterion, Field, GovernanceSettings, Match, Metadata, Mode, ModeOptions, Operator,
        Policy, PolicyDocument, PolicyId, PolicySettings, PrecedenceModel, PrecedenceOptions, Rule,
        RuleSet, RuleSetKind, UnknownPolicy,
    },
    schema,
    unknown::SystemBaseline,
    validate::ValidatedPolicy,
};

/// Which built-in policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Builtin {
    /// No policy yet: audit mode.
    FirstInstall,
    /// Both cache files failed: allow the OS and Palisade, block the rest.
    Emergency,
}

/// Who enforces Palisade's decisions on this device (ADR 0002's
/// `enforcement_strategy`), which decides the emergency policy's mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Enforcement {
    /// `layered` or `driver_only`: the Palisade driver enforces, so the
    /// emergency policy runs in enforce mode. The default, because it is
    /// the stricter reading.
    #[default]
    Palisade,
    /// `native_only`: there is no Palisade pre-execution enforcer. The
    /// emergency policy runs in audit mode, so events show what it would
    /// block, and the device reports `PolicyEmergencyUnenforced`. The
    /// installed native policy keeps enforcing (ADR 0018).
    NativeOnly,
}

/// One of Palisade's own images, for the emergency policy's allow.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SelfPin {
    /// SHA-256 of the image, as 64 hex digits.
    pub sha256: String,
    /// The publisher whose trusted signature it must carry.
    pub publisher: String,
}

/// What the agent knows about itself and the device, from its own
/// measurements, never from a bundle: the built-in policies are built from
/// it, and the system baseline is added to every bundle loaded.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentFacts {
    /// The OS publishers and flagged directories for the system baseline.
    pub baseline: Option<SystemBaseline>,
    /// Palisade's own images.
    pub self_pins: Vec<SelfPin>,
    /// Who enforces.
    pub enforcement: Enforcement,
}

/// The policy IDs of the built-in policies: fixed UUIDv7s, so events name
/// them the same way on every device.
const FIRST_INSTALL_ID: [u8; 16] = [
    0x01, 0x9a, 0xc0, 0x00, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];
const EMERGENCY_ID: [u8; 16] = [
    0x01, 0x9a, 0xc0, 0x00, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
];
/// The rule set holding the self pins.
const SELF_SET_ID: [u8; 16] = [
    0x01, 0x9a, 0xc0, 0x00, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
];
/// The first self-pin rule; rule `n` has `n` added to the last two bytes.
const SELF_RULE_BASE: [u8; 16] = [
    0x01, 0x9a, 0xc0, 0x00, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
];

#[expect(
    clippy::expect_used,
    reason = "fixed UUIDv7s; `builtins_validate_and_build` tests them"
)]
fn uuid(bytes: [u8; 16]) -> Uuid7 {
    Uuid7::from_bytes(bytes).expect("a fixed UUIDv7")
}

fn self_rule_id(n: u16) -> RuleId {
    let mut bytes = SELF_RULE_BASE;
    let [hi, lo] = n.to_be_bytes();
    bytes[14] = hi;
    bytes[15] = lo;
    RuleId::from(uuid(bytes))
}

impl Builtin {
    /// The policy document, without the system baseline (which is added
    /// after validation).
    pub fn document(self, facts: &AgentFacts) -> PolicyDocument {
        self.document_with(facts, true)
    }

    fn document_with(self, facts: &AgentFacts, pins: bool) -> PolicyDocument {
        let (id, name, mode) = match self {
            Self::FirstInstall => (
                FIRST_INSTALL_ID,
                "Built-in first-install policy",
                Mode::Audit,
            ),
            Self::Emergency => (
                EMERGENCY_ID,
                "Built-in emergency policy",
                match facts.enforcement {
                    Enforcement::Palisade => Mode::Enforce,
                    Enforcement::NativeOnly => Mode::Audit,
                },
            ),
        };
        let rule_sets = match self {
            Self::Emergency if pins && !facts.self_pins.is_empty() => {
                vec![self_set(&facts.self_pins)]
            }
            _ => Vec::new(),
        };
        PolicyDocument {
            schema_version: schema::CURRENT,
            policy: Policy {
                id: PolicyId(uuid(id)),
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
                rule_sets: rule_sets.iter().map(|s| s.id).collect(),
                scope: None,
                rule_set_scopes: Vec::new(),
                location_profiles: Vec::new(),
                // No catch-all allow, so nothing to confirm.
                confirm_permit_all: None,
                metadata: Metadata::default(),
            },
            rule_sets,
        }
    }

    /// The validated policy. Never fails: an input that does not build is
    /// left out, which only makes the policy stricter (see the module
    /// docs).
    pub fn policy(self, facts: &AgentFacts) -> ValidatedPolicy {
        let policy = self.document(facts).validate().unwrap_or_else(|errors| {
            tracing::error!(
                ?errors,
                "the built-in policy's self pins do not validate; they are left out"
            );
            self.bare(facts)
        });
        match (self, &facts.baseline) {
            (Self::Emergency, Some(baseline)) => {
                let fallback = policy.clone();
                policy.with_system_baseline(baseline).unwrap_or_else(|e| {
                    tracing::error!(error = %e, "the system baseline does not build; the emergency policy runs without it");
                    fallback
                })
            }
            _ => policy,
        }
    }

    /// The policy with no rules at all.
    fn bare(self, facts: &AgentFacts) -> ValidatedPolicy {
        #[expect(
            clippy::expect_used,
            reason = "a fixed document with no rules; `builtins_validate_and_build` tests it"
        )]
        self.document_with(facts, false)
            .validate()
            .expect("the built-in policies are valid")
    }
}

/// The allowlist of Palisade's own images: one rule per pin, matching the
/// hash and a trusted signature from the publisher, for every object type.
fn self_set(pins: &[SelfPin]) -> RuleSet {
    let rules = pins
        .iter()
        .zip(1_u16..)
        .map(|(pin, n)| Rule {
            id: self_rule_id(n),
            display_id: None,
            name: format!("Palisade image {n}"),
            description: None,
            enabled: true,
            activates_at: None,
            expires_at: None,
            on_expire: Default::default(),
            object_types: Vec::new(),
            match_: Match::All(vec![
                Match::Criterion(Criterion::new(
                    Field::HashSha256,
                    Operator::Equals,
                    [pin.sha256.clone()],
                )),
                Match::Criterion(Criterion::new(
                    Field::SignerPublisher,
                    Operator::Equals,
                    [pin.publisher.clone()],
                )),
            ]),
            catch_all: false,
            attribute: false,
            action: Action::Allow {},
            effects: Default::default(),
            order: None,
            priority: None,
            enforcement_override: Default::default(),
            scope: None,
            metadata: Default::default(),
        })
        .collect();
    RuleSet {
        id: RuleSetId::from(uuid(SELF_SET_ID)),
        name: "Palisade agent images".to_owned(),
        description: None,
        version: None,
        kind: RuleSetKind::Allowlist,
        mandatory: false,
        os: Default::default(),
        read_only: true,
        hidden: false,
        mode_override: None,
        allow_child_suppress: None,
        category_path: None,
        band: 0,
        rules,
        metadata: Metadata::default(),
    }
}

#[cfg(test)]
mod tests {
    use palisade_policy::engine::{Engine, EngineConfig};

    use super::*;

    fn pin() -> SelfPin {
        SelfPin {
            sha256: "c".repeat(64),
            publisher: "Palisade".into(),
        }
    }

    fn baseline() -> SystemBaseline {
        SystemBaseline {
            publishers: vec!["Operating System Publisher".into()],
            writable_dirs: Vec::new(),
        }
    }

    #[test]
    fn builtins_validate_and_build() {
        for bytes in [FIRST_INSTALL_ID, EMERGENCY_ID, SELF_SET_ID, SELF_RULE_BASE] {
            assert!(Uuid7::from_bytes(bytes).is_some());
        }
        let full = AgentFacts {
            baseline: Some(baseline()),
            self_pins: vec![pin()],
            enforcement: Enforcement::Palisade,
        };
        for facts in [AgentFacts::default(), full] {
            for (builtin, mode) in [
                (Builtin::FirstInstall, Mode::Audit),
                (Builtin::Emergency, Mode::Enforce),
            ] {
                let policy = builtin.policy(&facts);
                assert_eq!(policy.document().policy.mode, mode);
                Engine::new(policy, EngineConfig::default()).unwrap();
            }
        }
        assert_ne!(
            Builtin::FirstInstall
                .document(&AgentFacts::default())
                .policy
                .id,
            Builtin::Emergency
                .document(&AgentFacts::default())
                .policy
                .id
        );
        assert_ne!(self_rule_id(1), self_rule_id(2));
    }

    #[test]
    fn the_emergency_policy_holds_only_the_pins_and_the_baseline() {
        let facts = AgentFacts {
            baseline: Some(baseline()),
            self_pins: vec![pin(), pin()],
            enforcement: Enforcement::Palisade,
        };
        let doc = Builtin::Emergency.policy(&facts).into_document();
        assert_eq!(doc.rule_sets.len(), 2);
        assert_eq!(doc.rule_sets[0].rules.len(), 2);
        assert!(
            doc.rule_sets[0]
                .rules
                .iter()
                .all(|r| r.action == Action::Allow {})
        );
        assert!(palisade_policy::unknown::baseline::is_system_baseline(
            &doc.rule_sets[1]
        ));
        // The first-install policy never takes them.
        assert!(
            Builtin::FirstInstall
                .policy(&facts)
                .document()
                .rule_sets
                .is_empty()
        );
    }

    #[test]
    fn native_only_runs_the_emergency_policy_in_audit_mode() {
        let facts = AgentFacts {
            enforcement: Enforcement::NativeOnly,
            ..AgentFacts::default()
        };
        assert_eq!(
            Builtin::Emergency.policy(&facts).document().policy.mode,
            Mode::Audit
        );
        assert_eq!(Enforcement::default(), Enforcement::Palisade);
    }

    #[test]
    fn inputs_that_do_not_build_are_left_out() {
        // A pin that is not a hash fails validation: no pins at all.
        let facts = AgentFacts {
            self_pins: vec![SelfPin {
                sha256: "not a hash".into(),
                publisher: "Palisade".into(),
            }],
            baseline: Some(SystemBaseline::default()),
            enforcement: Enforcement::Palisade,
        };
        let policy = Builtin::Emergency.policy(&facts);
        assert!(policy.document().rule_sets.is_empty());
        assert_eq!(policy.document().policy.mode, Mode::Enforce);
    }
}
