//! The typed output of an evaluation (#34).
//!
//! Every consumer gets the same [`Decision`]: the agent acts on it, the
//! decision trace explains it (#41), and events embed it (#16). Its JSON
//! form is stable: fields are always present, in declaration order, with
//! `null` for an absent value, and the snapshot tests in
//! `tests/snapshots/decision/` fail on any change to it.
//!
//! This module builds the decision of one terminal rule
//! ([`Decision::from_rule`]) and the implicit deny for an object no rule
//! decides ([`Decision::implicit_deny`]), both as enforce mode sees them.
//! The pipeline in [`crate::evaluate`] combines the matching rules (#35):
//! it adds the `audit` annotations, the rules the deciding rule overrode,
//! and the trust-source grants. Applying a non-enforcing mode, which
//! changes [`Decision::outcome`] and keeps the enforce-mode result in
//! [`Decision::would_have_been`], is #36.

use core::fmt;

use serde::{Serialize, Serializer};

use crate::model::{
    Action, ActionKind, ContainmentDirective, ContainmentProfileRef, ElevationAuth,
    ElevationCondition, ElevationDirective, Mode, Policy, PolicyId, RequestTemplateRef,
    ResolvedEffects, Rule, RuleId, RuleSet, RuleSetId, TokenProfileRef, TrustMode,
    TrustSourceDirective,
};

/// What happened to the object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// It runs.
    Allowed,
    /// It does not run.
    Blocked,
    /// It runs, but would have been blocked in enforce mode.
    AllowedAudit,
    /// It runs, because an override session allows what would have been
    /// blocked (#9).
    AllowedOverride,
    /// It was excluded by an `ignore` rule: no decision is logged.
    Ignored,
}

/// Why the decision was made. The `snake_case` name is part of the API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    /// An allow rule decided.
    ExplicitAllow,
    /// A deny rule decided.
    ExplicitDeny,
    /// A rule in a mandatory rule set decided (ADR 0004).
    MandatoryDeny,
    /// No rule decided, and unknown objects are denied (#39).
    ImplicitDenyUnknown,
    /// A non-enforcing mode allowed what enforce mode would block (#36).
    AuditModeWouldBlock,
    /// An override session allowed what would have been blocked (#9).
    OverrideSession,
    /// An `ignore` rule excluded the object.
    Exclusion,
}

/// A rule's human short ID, `R-` and 6 to 12 digits, kept as a number and
/// its digit count so that [`RuleRef`] stays `Copy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DisplayId {
    number: u64,
    digits: u8,
}

impl DisplayId {
    /// Parses `R-` followed by 6 to 12 ASCII digits, the form validation
    /// accepts.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let digits = text.strip_prefix("R-")?;
        if !(6..=12).contains(&digits.len()) || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(Self {
            number: digits.parse().ok()?,
            digits: u8::try_from(digits.len()).ok()?,
        })
    }
}

impl fmt::Display for DisplayId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "R-{:0width$}",
            self.number,
            width = usize::from(self.digits)
        )
    }
}

impl Serialize for DisplayId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Which rule, in which revision of which policy. Small and `Copy`, so it
/// can be kept for every match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct RuleRef {
    /// The rule's stable ID.
    pub rule_id: RuleId,
    /// The rule's human short ID, if it has one.
    pub display_id: Option<DisplayId>,
    /// The rule set that holds the rule.
    pub rule_set_id: RuleSetId,
    /// The policy that references the rule set.
    pub policy_id: PolicyId,
    /// The policy revision the decision was made under.
    pub policy_revision: u64,
}

impl RuleRef {
    /// Refers to `rule`, held by `set`, in `policy`. A `display_id` that is
    /// not well formed is left out; a validated document has none.
    #[must_use]
    pub fn new(policy: &Policy, set: &RuleSet, rule: &Rule) -> Self {
        Self {
            rule_id: rule.id,
            display_id: rule.display_id.as_deref().and_then(DisplayId::parse),
            rule_set_id: set.id,
            policy_id: policy.id,
            policy_revision: policy.revision,
        }
    }
}

/// A trace ID for one evaluation: 16 bytes, written as 32 lowercase
/// hexadecimal digits. The caller supplies it, because evaluation is pure
/// and has no random source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TraceId(pub [u8; 16]);

impl fmt::Display for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl Serialize for TraceId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// An approval request the user may raise against a block (#11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct RequestDirective {
    /// The request template, or `null` for the default.
    pub template: Option<RequestTemplateRef>,
}

/// Run inside a containment profile (#14), as a decision carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct Containment {
    /// The containment profile.
    pub profile_id: ContainmentProfileRef,
}

impl From<&ContainmentDirective> for Containment {
    fn from(d: &ContainmentDirective) -> Self {
        Self {
            profile_id: d.profile_id,
        }
    }
}

/// Run with an elevated token (#12), as a decision carries it: every field
/// is present, `null` when absent.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct Elevation {
    /// The access token profile.
    pub token_profile: TokenProfileRef,
    /// When to elevate.
    pub condition: ElevationCondition,
    /// The reason prompt, or `null` if no reason is asked for.
    pub reason_prompt: Option<String>,
    /// The confirmation asked for.
    pub auth: ElevationAuth,
}

impl From<&ElevationDirective> for Elevation {
    fn from(d: &ElevationDirective) -> Self {
        Self {
            token_profile: d.token_profile,
            condition: d.condition,
            reason_prompt: d.reason_prompt.clone(),
            auth: d.auth,
        }
    }
}

/// A trust-source designation that applies to the object, and the rule it
/// came from (#9), as a decision carries it: every field is present.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct TrustGrant {
    /// The `trust_source` rule.
    pub rule: RuleRef,
    /// Which writes are trusted.
    pub mode: TrustMode,
    /// The folders whose new content becomes trusted.
    pub scope_paths: Vec<String>,
    /// Whether written files get a persistent trust claim.
    pub tag_output: bool,
}

impl TrustGrant {
    /// The grant of a `trust_source` rule's directive.
    #[must_use]
    pub fn new(rule: RuleRef, d: &TrustSourceDirective) -> Self {
        Self {
            rule,
            mode: d.mode,
            scope_paths: d.scope_paths.clone(),
            tag_output: d.tag_output,
        }
    }
}

/// The directives a decision carries for the components that act on it.
/// The engine passes them through; their meaning belongs to the owning
/// epics. These are separate from the model's directive types, which leave
/// defaults out when written, so that a decision's JSON always has every
/// field.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Directives {
    /// Run inside this containment profile (#14).
    pub containment: Option<Containment>,
    /// Run with this elevation (#12).
    pub elevation: Option<Elevation>,
    /// Treat the process as a trusted source (#9): the grant of every
    /// matching `trust_source` rule, by rule ID. Only an allowed object
    /// gets grants (#35).
    pub trust_sources: Vec<TrustGrant>,
    /// Terminate running instances that match.
    pub kill_running: bool,
    /// The user may ask for approval.
    pub request: Option<RequestDirective>,
}

impl Directives {
    /// The directives of the action of a deciding rule.
    #[must_use]
    pub fn of(action: &Action) -> Self {
        let mut d = Self::default();
        match action {
            Action::Deny(o) => {
                d.kill_running = o.kill_running;
                d.request = o.allow_request.then_some(RequestDirective {
                    template: o.request_template,
                });
            }
            Action::AllowContained(c) => d.containment = Some(c.into()),
            Action::AllowElevated(e) => d.elevation = Some(e.into()),
            Action::Allow {}
            | Action::Audit {}
            | Action::TrustSource(_)
            | Action::Ignore {}
            | Action::Defer {} => {}
        }
        d
    }
}

/// The typed result of evaluating one object.
///
/// The fields are read through accessors, so a decision is always one of
/// the forms its constructors build. Serialising it gives the stable JSON
/// form described in the module documentation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Decision {
    outcome: Outcome,
    would_have_been: Outcome,
    action: ActionKind,
    matched_rule: Option<RuleRef>,
    overridden: Vec<RuleRef>,
    annotations: Vec<RuleRef>,
    mode: Mode,
    directives: Directives,
    effects: ResolvedEffects,
    reason_code: ReasonCode,
    trace_id: TraceId,
}

impl Decision {
    /// The decision of `rule`, held by `set`, which `policy` references, as
    /// enforce mode sees it. The caller has already found that the rule
    /// matches and wins (#35).
    ///
    /// Returns `None` for a disabled rule, which never decides, and for an
    /// action that does not decide by itself (`audit`, `defer`,
    /// `trust_source`; see [`ActionKind::is_terminal`]).
    #[must_use]
    pub fn from_rule(
        policy: &Policy,
        set: &RuleSet,
        rule: &Rule,
        trace_id: TraceId,
    ) -> Option<Self> {
        if !rule.enabled {
            return None;
        }
        let kind = rule.action.kind();
        let (outcome, reason_code) = match kind {
            ActionKind::Allow | ActionKind::AllowContained | ActionKind::AllowElevated => {
                (Outcome::Allowed, ReasonCode::ExplicitAllow)
            }
            ActionKind::Deny if set.mandatory => (Outcome::Blocked, ReasonCode::MandatoryDeny),
            ActionKind::Deny => (Outcome::Blocked, ReasonCode::ExplicitDeny),
            ActionKind::Ignore => (Outcome::Ignored, ReasonCode::Exclusion),
            ActionKind::Audit | ActionKind::Defer | ActionKind::TrustSource => return None,
        };
        Some(Self {
            outcome,
            would_have_been: outcome,
            action: kind,
            matched_rule: Some(RuleRef::new(policy, set, rule)),
            overridden: Vec::new(),
            annotations: Vec::new(),
            mode: Mode::Enforce,
            directives: Directives::of(&rule.action),
            effects: rule.effects.resolve(kind),
            reason_code,
            trace_id,
        })
    }

    /// The implicit deny for an object that no rule decides, as enforce
    /// mode sees it (#39). It has the effects of a `deny` with default
    /// effect flags.
    #[must_use]
    pub fn implicit_deny(trace_id: TraceId) -> Self {
        Self {
            outcome: Outcome::Blocked,
            would_have_been: Outcome::Blocked,
            action: ActionKind::Deny,
            matched_rule: None,
            overridden: Vec::new(),
            annotations: Vec::new(),
            mode: Mode::Enforce,
            directives: Directives::default(),
            effects: crate::model::Effects::default().resolve(ActionKind::Deny),
            reason_code: ReasonCode::ImplicitDenyUnknown,
            trace_id,
        }
    }

    /// What happened to the object, in the effective mode.
    #[must_use]
    pub const fn outcome(&self) -> Outcome {
        self.outcome
    }

    /// The outcome in enforce mode. Equal to [`outcome`](Self::outcome) in
    /// enforce mode; in the others, the simulated result that readiness
    /// reports use (#41, #5). Always set.
    #[must_use]
    pub const fn would_have_been(&self) -> Outcome {
        self.would_have_been
    }

    /// The action that decided. `deny` for the implicit deny.
    #[must_use]
    pub const fn action(&self) -> ActionKind {
        self.action
    }

    /// The rule that decided, or `None` for the implicit deny.
    #[must_use]
    pub const fn matched_rule(&self) -> Option<&RuleRef> {
        self.matched_rule.as_ref()
    }

    /// The rules that matched and would have decided or attached a
    /// grant, but lost to [`matched_rule`](Self::matched_rule), by rule
    /// ID (#35). Empty when one rule matched alone.
    #[must_use]
    pub fn overridden(&self) -> &[RuleRef] {
        &self.overridden
    }

    /// The `audit` rules that also matched, by rule ID.
    #[must_use]
    pub fn annotations(&self) -> &[RuleRef] {
        &self.annotations
    }

    /// Adds what the pipeline gathered besides the deciding rule (#35).
    /// Each list is sorted by rule ID, so the decision does not depend on
    /// the order in which rules were evaluated.
    pub(crate) fn with_context(
        mut self,
        mut overridden: Vec<RuleRef>,
        mut annotations: Vec<RuleRef>,
        mut trust_sources: Vec<TrustGrant>,
    ) -> Self {
        overridden.sort_by_key(|r| r.rule_id);
        annotations.sort_by_key(|r| r.rule_id);
        trust_sources.sort_by_key(|g| g.rule.rule_id);
        self.overridden = overridden;
        self.annotations = annotations;
        self.directives.trust_sources = trust_sources;
        self
    }

    /// The effective mode the decision was made in (#36).
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.mode
    }

    /// What the acting components must do.
    #[must_use]
    pub const fn directives(&self) -> &Directives {
        &self.directives
    }

    /// The effect flags, with defaults applied.
    #[must_use]
    pub const fn effects(&self) -> &ResolvedEffects {
        &self.effects
    }

    /// Why the decision was made.
    #[must_use]
    pub const fn reason_code(&self) -> ReasonCode {
        self.reason_code
    }

    /// The trace ID of the evaluation.
    #[must_use]
    pub const fn trace_id(&self) -> TraceId {
        self.trace_id
    }
}

#[cfg(test)]
mod tests;
