//! Builders for tests: policies, rule sets, rules, match trees, object facts
//! and evaluation contexts (#25).
//!
//! Only compiled with the `test-util` feature, which only
//! `[dev-dependencies]` turn on (`cargo xtask check-manifests` enforces it),
//! so none of this reaches a release build. Other crates' tests use it with
//!
//! ```toml
//! [dev-dependencies]
//! palisade-policy = { workspace = true, features = ["test-util"] }
//! ```
//!
//! Every builder starts from the smallest valid value and changes only what
//! the test sets, so a test states what matters to it and nothing else.
//! IDs are deterministic: the same calls give the same document, so
//! snapshots of it are stable.
//!
//! ```
//! use palisade_policy::model::ObjectType;
//! use palisade_policy::test_util::{PolicyBuilder, RuleBuilder, RuleSetBuilder, facts, hash, subject};
//!
//! let policy = PolicyBuilder::new()
//!     .rule_set(RuleSetBuilder::allowlist(1).rule(RuleBuilder::allow(1, hash('a'))))
//!     .validate();
//! let facts = facts().sha256('a');
//! let decision = subject(&facts).object_type(ObjectType::Executable).decide(&policy);
//! assert_eq!(decision.outcome(), palisade_policy::decision::Outcome::Allowed);
//! ```

#![allow(
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "test builders panic with a message when a test builds something invalid"
)]

use palisade_core::path::VolumeMap;
use palisade_core::{PolicyId, RuleId, RuleSetId, SchemaVersion, Uuid7};

use crate::context::EvaluationContext;
use crate::decision::{Decision, TraceId};
use crate::evaluate::{Evaluator, Subject};
use crate::facts::{
    ObjectFacts, PathFact, PathVariables, SignatureSource, SignerFact, SignerStatus,
};
use crate::mode::DeviceState;
use crate::model::{
    Action, Criterion, Field, Match, Metadata, Mode, ObjectType, Operator, Policy, PolicyDocument,
    PrecedenceModel, Rule, RuleSet, RuleSetKind,
};
use crate::validate::ValidatedPolicy;

/// The trace ID every [`SubjectBuilder::decide`] uses, so decisions are
/// reproducible.
pub const TRACE: TraceId = TraceId([7; 16]);

/// A UUIDv7 with a fixed time and variant, whose last 12 bits are `kind`
/// and whose low 32 bits are `n`. IDs of different kinds never collide.
fn uuid7(kind: u16, n: u32) -> Uuid7 {
    let text = format!("01936b2e-8c4a-7{:03x}-9f21-0000{n:08x}", kind & 0xfff);
    text.parse().expect("a valid UUIDv7")
}

/// The ID of policy `n`.
#[must_use]
pub fn policy_id(n: u32) -> PolicyId {
    PolicyId::from(uuid7(1, n))
}

/// The ID of rule set `n`.
#[must_use]
pub fn rule_set_id(n: u32) -> RuleSetId {
    RuleSetId::from(uuid7(2, n))
}

/// The ID of rule `n`.
#[must_use]
pub fn rule_id(n: u32) -> RuleId {
    RuleId::from(uuid7(3, n))
}

/// A 64-character SHA-256 made of one repeated hex digit, such as
/// `aaaa…`. Different digits give different hashes.
#[must_use]
pub fn sha256_of(digit: char) -> String {
    assert!(digit.is_ascii_hexdigit(), "{digit:?} is not a hex digit");
    std::iter::repeat_n(digit.to_ascii_lowercase(), 64).collect()
}

/// One criterion.
#[must_use]
pub fn criterion(field: Field, operator: Operator, values: &[&str]) -> Match {
    Match::Criterion(Criterion {
        field,
        operator,
        values: values.iter().map(|v| (*v).to_owned()).collect(),
        case_sensitive: None,
        anchored: None,
        match_ads: None,
        include_sub_ous: None,
        safety_critical: false,
        signer: None,
    })
}

/// `hash.sha256 equals` [`sha256_of`]`(digit)`.
#[must_use]
pub fn hash(digit: char) -> Match {
    criterion(Field::HashSha256, Operator::Equals, &[&sha256_of(digit)])
}

/// `signer.publisher equals publisher`.
#[must_use]
pub fn publisher(publisher: &str) -> Match {
    criterion(Field::SignerPublisher, Operator::Equals, &[publisher])
}

/// `path.directory starts_with dir`.
#[must_use]
pub fn under(dir: &str) -> Match {
    criterion(Field::PathDirectory, Operator::StartsWith, &[dir])
}

/// Every child matches.
#[must_use]
pub fn all(children: Vec<Match>) -> Match {
    Match::All(children)
}

/// Any child matches.
#[must_use]
pub fn any(children: Vec<Match>) -> Match {
    Match::Any(children)
}

/// The child does not match.
#[must_use]
pub fn not(child: Match) -> Match {
    Match::Not(Box::new(child))
}

/// A rule. Starts enabled, for executables and installers.
#[derive(Clone, Debug)]
#[must_use]
pub struct RuleBuilder(Rule);

impl RuleBuilder {
    /// Rule `n`, matching `tree`, with `action`.
    pub fn new(n: u32, tree: Match, action: Action) -> Self {
        Self(Rule {
            id: rule_id(n),
            display_id: None,
            name: format!("Rule {n}"),
            description: None,
            enabled: true,
            activates_at: None,
            expires_at: None,
            on_expire: crate::model::OnExpire::default(),
            object_types: vec![ObjectType::Executable, ObjectType::Installer],
            match_: tree,
            action,
            effects: crate::model::Effects::default(),
            order: None,
            priority: None,
            enforcement_override: crate::model::EnforcementOverride::default(),
            scope: None,
            metadata: crate::model::RuleMetadata::default(),
        })
    }

    /// An allow rule.
    pub fn allow(n: u32, tree: Match) -> Self {
        Self::new(n, tree, Action::Allow {})
    }

    /// A deny rule with default options.
    pub fn deny(n: u32, tree: Match) -> Self {
        Self::new(n, tree, Action::deny())
    }

    /// An audit rule.
    pub fn audit(n: u32, tree: Match) -> Self {
        Self::new(n, tree, Action::Audit {})
    }

    /// The object types it applies to. Empty means every type.
    pub fn object_types(mut self, types: &[ObjectType]) -> Self {
        self.0.object_types = types.to_vec();
        self
    }

    /// Disables the rule.
    pub fn disabled(mut self) -> Self {
        self.0.enabled = false;
        self
    }

    /// The `first_match` position.
    pub fn order(mut self, order: u32) -> Self {
        self.0.order = Some(order);
        self
    }

    /// The `priority` model priority.
    pub fn priority(mut self, priority: i32) -> Self {
        self.0.priority = Some(priority);
        self
    }

    /// The rule.
    pub fn build(self) -> Rule {
        self.0
    }
}

/// A rule set. Starts empty, for Windows, not mandatory.
#[derive(Clone, Debug)]
#[must_use]
pub struct RuleSetBuilder(RuleSet);

impl RuleSetBuilder {
    /// Rule set `n` of `kind`.
    pub fn new(n: u32, kind: RuleSetKind) -> Self {
        Self(RuleSet {
            id: rule_set_id(n),
            name: format!("Rule set {n}"),
            description: None,
            version: None,
            kind,
            mandatory: false,
            os: crate::model::Os::default(),
            read_only: false,
            hidden: false,
            mode_override: None,
            allow_child_suppress: None,
            category_path: None,
            band: 0,
            rules: Vec::new(),
            metadata: Metadata::default(),
        })
    }

    /// An allowlist.
    pub fn allowlist(n: u32) -> Self {
        Self::new(n, RuleSetKind::Allowlist)
    }

    /// A blocklist.
    pub fn blocklist(n: u32) -> Self {
        Self::new(n, RuleSetKind::Blocklist)
    }

    /// A mandatory blocklist: its denies are evaluated first and cannot be
    /// overridden (ADR 0004).
    pub fn mandatory_blocklist(n: u32) -> Self {
        let mut b = Self::blocklist(n);
        b.0.mandatory = true;
        b
    }

    /// A mixed rule set.
    pub fn mixed(n: u32) -> Self {
        Self::new(n, RuleSetKind::Mixed)
    }

    /// Adds a rule.
    pub fn rule(mut self, rule: RuleBuilder) -> Self {
        self.0.rules.push(rule.build());
        self
    }

    /// Marks the rule set curated (read-only).
    pub fn read_only(mut self) -> Self {
        self.0.read_only = true;
        self
    }

    /// The rule set.
    pub fn build(self) -> RuleSet {
        self.0
    }
}

/// A policy document. Starts as policy 1, revision 1, `enforce`,
/// `deny_wins`, with no rule sets.
#[derive(Clone, Debug)]
#[must_use]
pub struct PolicyBuilder(PolicyDocument);

impl Default for PolicyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyBuilder {
    /// The smallest valid policy.
    pub fn new() -> Self {
        Self(PolicyDocument {
            schema_version: crate::schema::CURRENT,
            policy: Policy {
                id: policy_id(1),
                name: "Test policy".to_owned(),
                description: None,
                revision: 1,
                precedence_model: PrecedenceModel::default(),
                precedence_options: crate::model::PrecedenceOptions::default(),
                mode: Mode::Enforce,
                mode_options: crate::model::ModeOptions::default(),
                settings: crate::model::PolicySettings::default(),
                unknown: crate::model::UnknownPolicy::default(),
                governance: crate::model::GovernanceSettings::default(),
                rule_sets: Vec::new(),
                scope: None,
                rule_set_scopes: Vec::new(),
                location_profiles: Vec::new(),
                metadata: Metadata::default(),
            },
            rule_sets: Vec::new(),
        })
    }

    /// The precedence model.
    pub fn precedence(mut self, model: PrecedenceModel) -> Self {
        self.0.policy.precedence_model = model;
        self
    }

    /// The base mode. [`SubjectBuilder::decide`] decides as enforce mode
    /// sees it, whatever this is; [`SubjectBuilder::decide_in_mode`] applies
    /// it.
    pub fn mode(mut self, mode: Mode) -> Self {
        self.0.policy.mode = mode;
        self
    }

    /// The schema version the document says it was written for.
    pub fn schema_version(mut self, version: SchemaVersion) -> Self {
        self.0.schema_version = version;
        self
    }

    /// Adds a rule set, and references it from the policy, in order.
    pub fn rule_set(mut self, set: RuleSetBuilder) -> Self {
        let set = set.build();
        self.0.policy.rule_sets.push(set.id);
        self.0.rule_sets.push(set);
        self
    }

    /// The document, unvalidated.
    pub fn build(self) -> PolicyDocument {
        self.0
    }

    /// The document, validated. Panics with the validation errors if it is
    /// not valid.
    pub fn validate(self) -> ValidatedPolicy {
        match self.0.validate() {
            Ok(policy) => policy,
            Err(errors) => panic!("the test policy is not valid: {errors:#?}"),
        }
    }
}

/// Object facts. Starts with no facts.
#[derive(Clone, Debug, Default)]
#[must_use]
pub struct FactsBuilder(ObjectFacts);

/// Starts a [`FactsBuilder`].
pub fn facts() -> FactsBuilder {
    FactsBuilder::default()
}

impl FactsBuilder {
    /// A hash or version-resource fact (`hash.*`, `meta.*`). Panics for any
    /// other field, which [`ObjectFacts`] would otherwise drop silently:
    /// use [`Self::path`] for `path.*`, [`Self::signer`] for `signer.*`, and
    /// [`context`] for user, device and session fields.
    pub fn with(mut self, field: Field, value: &str) -> Self {
        assert!(
            self.0.set(field, value),
            "{field:?} is not a stored fact; use .path(..), .signer(..) or context() instead"
        );
        self
    }

    /// `hash.sha256` = [`sha256_of`]`(digit)`.
    pub fn sha256(self, digit: char) -> Self {
        self.with(Field::HashSha256, &sha256_of(digit))
    }

    /// The path, not user-writable, on a fixed volume, with no volume
    /// mapping: a path an allow can trust.
    pub fn path(mut self, path: &str) -> Self {
        self.0 = self.0.with_path(
            PathFact::new(path, &VolumeMap::new())
                .with_user_writable(false)
                .with_volume(crate::unknown::VolumeKind::Fixed),
        );
        self
    }

    /// The path, writable by a standard user.
    pub fn user_writable_path(mut self, path: &str) -> Self {
        self.0 = self
            .0
            .with_path(PathFact::new(path, &VolumeMap::new()).with_user_writable(true));
        self
    }

    /// The kind of volume the path is on (#39). Call after [`Self::path`]
    /// or [`Self::user_writable_path`]; without one it panics.
    pub fn volume(mut self, volume: crate::unknown::VolumeKind) -> Self {
        let path = self.0.path.take().expect("set the path before its volume");
        self.0 = self.0.with_path(path.with_volume(volume));
        self
    }

    /// The origins the agent's origin collection found (#39). An empty list
    /// means it ran and found nothing: origin `unknown`. Without this call
    /// the facts have no origin fact at all, which stage 6 treats as missing.
    pub fn origins(mut self, origins: &[crate::model::OriginClass]) -> Self {
        self.0 = self.0.with_origin(origins.iter().copied());
        self
    }

    /// One valid embedded signature by `publisher`.
    pub fn signed_by(self, publisher: &str) -> Self {
        self.signer(SignerStatus::Valid, publisher)
    }

    /// One embedded signature by `publisher` with `status`.
    pub fn signer(mut self, status: SignerStatus, publisher: &str) -> Self {
        let mut signers = self.0.signers.clone().unwrap_or_default();
        signers.push(SignerFact {
            status,
            source: SignatureSource::Embedded,
            publisher: Some(publisher.to_owned()),
            issuer: None,
            leaf_thumbprint_sha256: None,
            details: Default::default(),
        });
        self.0 = self.0.with_signers(signers);
        self
    }

    /// The facts.
    pub fn build(self) -> ObjectFacts {
        self.0
    }
}

/// An evaluation context. Starts with no facts: every context criterion is
/// unknown.
#[derive(Clone, Debug, Default)]
#[must_use]
pub struct ContextBuilder(EvaluationContext);

/// Starts a [`ContextBuilder`].
pub fn context() -> ContextBuilder {
    ContextBuilder::default()
}

impl ContextBuilder {
    /// The user's SID and groups.
    pub fn user(mut self, sid: &str, groups: &[&str]) -> Self {
        self.0.user.sid = Some(sid.to_owned());
        self.0.user.groups = Some(groups.iter().map(|g| (*g).to_owned()).collect());
        self
    }

    /// Whether the user is an administrator.
    pub fn admin(mut self, is_admin: bool) -> Self {
        self.0.user.is_admin = Some(is_admin);
        self
    }

    /// The device's host name.
    pub fn hostname(mut self, hostname: &str) -> Self {
        self.0.device.hostname = Some(hostname.to_owned());
        self
    }

    /// The device's tags.
    pub fn device_tags(mut self, tags: &[&str]) -> Self {
        self.0.device.tags = Some(tags.iter().map(|t| (*t).to_owned()).collect());
        self
    }

    /// The context.
    pub fn build(self) -> EvaluationContext {
        self.0
    }
}

/// What to decide: an object of a type, with facts, in a context. Starts as
/// an executable, in an empty context, with no path variables.
#[derive(Debug)]
#[must_use]
pub struct SubjectBuilder<'a> {
    facts: &'a ObjectFacts,
    object_type: ObjectType,
    context: EvaluationContext,
    variables: PathVariables,
}

/// Starts a [`SubjectBuilder`] over `facts` (a [`FactsBuilder`] or the
/// [`ObjectFacts`] themselves).
pub fn subject<F: AsRef<ObjectFacts> + ?Sized>(facts: &F) -> SubjectBuilder<'_> {
    SubjectBuilder {
        facts: facts.as_ref(),
        object_type: ObjectType::Executable,
        context: EvaluationContext::new(),
        variables: PathVariables::new(),
    }
}

impl AsRef<ObjectFacts> for FactsBuilder {
    fn as_ref(&self) -> &ObjectFacts {
        &self.0
    }
}

impl<'a> SubjectBuilder<'a> {
    /// The object type.
    pub fn object_type(mut self, object_type: ObjectType) -> Self {
        self.object_type = object_type;
        self
    }

    /// The context.
    pub fn context(mut self, context: ContextBuilder) -> Self {
        self.context = context.build();
        self
    }

    /// The path variables.
    pub fn variables(mut self, variables: PathVariables) -> Self {
        self.variables = variables;
        self
    }

    fn as_subject(&self) -> Subject<'_> {
        Subject {
            object_type: self.object_type,
            facts: self.facts,
            variables: &self.variables,
            context: &self.context,
        }
    }

    /// Decides the subject against `policy` as enforce mode sees it
    /// ([`Evaluator::evaluate`]), with the trace ID [`TRACE`]. The policy's
    /// modes are not applied; use [`Self::decide_in_mode`] for that.
    #[must_use]
    pub fn decide(&self, policy: &ValidatedPolicy) -> Decision {
        let evaluator = Evaluator::new(policy).expect("a validated policy compiles");
        evaluator.evaluate(&self.as_subject(), TRACE)
    }

    /// Decides the subject on a connected device in the policy's own mode,
    /// with no override session and no lockdown ([`Evaluator::evaluate_in`]
    /// with [`DeviceState::of`]), with the trace ID [`TRACE`]. `None` when
    /// the device is disabled.
    #[must_use]
    pub fn decide_in_mode(&self, policy: &ValidatedPolicy) -> Option<Decision> {
        self.decide_on(policy, &DeviceState::of(&policy.document().policy))
    }

    /// Decides the subject on a device in `state` ([`Evaluator::evaluate_in`]),
    /// with the trace ID [`TRACE`].
    #[must_use]
    pub fn decide_on(&self, policy: &ValidatedPolicy, state: &DeviceState) -> Option<Decision> {
        let evaluator = Evaluator::new(policy).expect("a validated policy compiles");
        evaluator.evaluate_in(&self.as_subject(), state, TRACE)
    }
}

#[cfg(test)]
mod tests;
