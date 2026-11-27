//! Explanations for people: [`explain`] turns a [`Trace`] into an
//! [`ExplainDoc`], and the renderers write it as plain text (CLI),
//! Markdown (console) or one short sentence (tray).
//!
//! An explanation is built from messages ([`Message`]): a stable ID and
//! named arguments. The text comes from a [`Catalog`] of templates, so the
//! same document can be rendered in any language. The built-in catalog is
//! English ([`Catalog::english`]). A translation is a file in a subset of
//! the Fluent syntax: one `id = text` per line, `#` comments, and
//! `{ $name }` placeholders ([`Catalog::with_translation`]). A message the
//! translation lacks falls back to English.
//!
//! Explain never creates a rule. "What would allow this?" is the trace's
//! draft ([`Trace::allow_suggestion`]), described here and handed to the
//! approval and recommendation flows (#5, #11).

use std::collections::BTreeMap;

use serde::Serialize;

use super::record::{field_name, operator_name};
use super::{
    CriterionTrace, DraftIdentity, MatchRole, ModeStepKind, NearMiss, RuleStage, StageName,
    StageOutcome, Trace, TriState, UnknownEffect, WarningCode,
};
use crate::decision::{Outcome, ReasonCode, RuleRef};
use crate::model::{ActionKind, Field, FieldClass, Mode, Operator, PrecedenceModel};

/// How much an explanation says.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verbosity {
    /// The summary and the reason.
    Short,
    /// Adds the mode, the stage, unknown facts, warnings, "why not
    /// allowed?" and "what would allow this?".
    Normal,
    /// Adds every mode resolution step and every near miss.
    Detailed,
}

/// One message: a template ID and its arguments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Message {
    /// The template ID.
    pub id: &'static str,
    /// The arguments, by name.
    pub args: BTreeMap<&'static str, String>,
}

impl Message {
    fn new(id: &'static str) -> Self {
        Self {
            id,
            args: BTreeMap::new(),
        }
    }

    fn arg(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.args.insert(name, value.into());
        self
    }
}

/// One row of the table of matching rules.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TableRow {
    /// The rule's short ID, or its rule ID.
    pub rule: String,
    /// Its name.
    pub name: String,
    /// Its action.
    pub action: &'static str,
    /// Its stage.
    pub stage: &'static str,
    /// The part it played.
    pub role: &'static str,
}

/// An explanation of one decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExplainDoc {
    /// The verbosity it was built at.
    pub verbosity: Verbosity,
    /// One sentence: what happened.
    pub summary: Message,
    /// Why: the deciding rule's criteria that a person can act on, such as
    /// a group membership. `null` when there is nothing more to say.
    pub reason: Option<Message>,
    /// The body.
    pub paragraphs: Vec<Message>,
    /// "Why not allowed?": the rules that would have allowed the object,
    /// and what kept each from matching.
    pub why_not: Vec<Message>,
    /// "What would allow this?": a description of the trace's draft rule.
    pub suggestion: Option<Message>,
    /// The rules that matched.
    pub table: Vec<TableRow>,
}

/// Builds the explanation of a trace.
#[must_use]
pub fn explain(trace: &Trace, verbosity: Verbosity) -> ExplainDoc {
    let mut doc = ExplainDoc {
        verbosity,
        summary: summary(trace),
        reason: reason(trace),
        paragraphs: Vec::new(),
        why_not: Vec::new(),
        suggestion: None,
        table: Vec::new(),
    };
    if verbosity == Verbosity::Short {
        return doc;
    }
    doc.paragraphs
        .push(Message::new("mode").arg("mode", mode_name(trace.effective_mode)));
    if verbosity == Verbosity::Detailed {
        for s in &trace.mode_resolution {
            if s.kind == ModeStepKind::Effective || s.kind == ModeStepKind::Applied || s.applied {
                let m = if s.detail.is_empty() {
                    Message::new("mode-step")
                } else {
                    Message::new("mode-step-detail").arg("detail", s.detail.clone())
                };
                doc.paragraphs.push(
                    m.arg("step", mode_step_name(s.kind))
                        .arg("mode", mode_name(s.mode)),
                );
            }
        }
    }
    if let Some(stage) = trace
        .stages
        .iter()
        .find(|s| s.outcome == StageOutcome::Decided)
    {
        doc.paragraphs.push(
            Message::new("stage")
                .arg("stage", stage_name(stage.name))
                .arg("model", model_name(trace)),
        );
    }
    let overridden = trace
        .matched
        .iter()
        .filter(|m| m.role == MatchRole::Overridden)
        .count();
    if overridden > 0 {
        doc.paragraphs
            .push(Message::new("overridden").arg("count", overridden.to_string()));
    }
    if trace
        .decision
        .as_ref()
        .and_then(|d| d.unknown())
        .is_some_and(|u| u.fallback == Some(crate::unknown::FallbackReason::PolicyOutOfScope))
    {
        doc.paragraphs.push(Message::new("unknown-out-of-scope"));
    }
    for u in &trace.unknown_facts {
        for e in &u.effects {
            doc.paragraphs.push(
                Message::new(match e {
                    UnknownEffect::AllowNotApplied => "unknown-allow",
                    UnknownEffect::DenyNotApplied => "unknown-deny",
                    UnknownEffect::DenyAppliedFailClosed => "unknown-deny-closed",
                    UnknownEffect::AnnotationNotApplied => "unknown-audit",
                })
                .arg("field", field_name(u.field)),
            );
        }
    }
    for w in &trace.warnings {
        let (id, alone) = warning_id(w.code);
        doc.paragraphs.push(if w.rules.is_empty() {
            Message::new(alone)
        } else {
            Message::new(id).arg(
                "rules",
                w.rules
                    .iter()
                    .map(rule_label)
                    .collect::<Vec<_>>()
                    .join(", "),
            )
        });
        for d in &w.details {
            doc.paragraphs
                .push(Message::new("warning-detail").arg("detail", d.clone()));
        }
    }
    for s in &trace.scope_rejections {
        let m = Message::new("scope-rejected")
            .arg("rule", named(&s.name, &s.rule))
            .arg("level", s.level.replace('_', " "));
        doc.paragraphs.push(match s.dimension {
            Some(d) => m.arg("dimension", d),
            None => m.arg("dimension", "scope"),
        });
    }
    for i in &trace.inactive_matches {
        doc.paragraphs.push(
            Message::new("inactive")
                .arg("rule", named(&i.name, &i.rule))
                .arg("action", i.action.as_str()),
        );
    }
    let blocked = trace
        .decision
        .as_ref()
        .is_some_and(|d| d.would_have_been().stops());
    // "Why not allowed?" lists the near misses that would have let the
    // object run: for a block or a would-block, and at `detailed` for
    // anything. Other near misses (a deny that nearly matched) are
    // paragraphs at `detailed`.
    for n in &trace.near_misses {
        let Some(m) = why_not(n) else { continue };
        if n.action.permits() {
            if blocked || verbosity == Verbosity::Detailed {
                doc.why_not.push(m);
            }
        } else if verbosity == Verbosity::Detailed {
            doc.paragraphs.push(m);
        }
    }
    if let Some(s) = &trace.allow_suggestion {
        let mut m = Message::new(match s.identity {
            DraftIdentity::Hash => "suggest-hash",
            DraftIdentity::PublisherProductVersion => "suggest-publisher-product-version",
            DraftIdentity::PublisherProduct => "suggest-publisher-product",
            DraftIdentity::Publisher => "suggest-publisher",
            DraftIdentity::Path => "suggest-path",
        });
        // What adding the draft would do, claiming no more than the
        // evaluator would decide: a mandatory deny always blocks, and under
        // `deny_wins` so does any matching deny. Under the other models the
        // deny may still win. With no deny matched, the draft is the only
        // policy candidate, so it allows the object under every model.
        let effect = if s.caveats.contains(&"mandatory_deny_matched") {
            "mandatory"
        } else if s.caveats.contains(&"deny_rule_matched") {
            if trace.precedence_model == PrecedenceModel::DenyWins {
                "deny_wins"
            } else {
                "deny"
            }
        } else {
            "allow"
        };
        m = m.arg("effect", effect);
        doc.suggestion = Some(m);
    }
    doc.table = trace
        .matched
        .iter()
        .map(|m| TableRow {
            rule: rule_label(&m.rule),
            name: m.name.clone(),
            action: m.action.as_str(),
            stage: rule_stage_name(m.stage),
            role: match m.role {
                MatchRole::Decided => "decided",
                MatchRole::Overridden => "overridden",
                MatchRole::Annotation => "annotation",
                MatchRole::Granted => "granted",
            },
        })
        .collect();
    doc
}

fn summary(trace: &Trace) -> Message {
    let Some(d) = &trace.decision else {
        return Message::new("summary-disabled");
    };
    let rule = trace
        .decisive
        .as_ref()
        .map(|r| named(&r.name, &r.rule))
        .unwrap_or_default();
    let object = trace.object_type.to_string();
    match d.reason_code() {
        ReasonCode::ExplicitAllow => Message::new("summary-allowed").arg("rule", rule),
        ReasonCode::ExplicitDeny => Message::new("summary-blocked").arg("rule", rule),
        ReasonCode::MandatoryDeny => Message::new("summary-mandatory").arg("rule", rule),
        ReasonCode::ImplicitDenyUnknown => Message::new("summary-implicit").arg("object", object),
        // The unknown-application policy (#39).
        ReasonCode::UnknownRestricted => {
            Message::new("summary-unknown-restricted").arg("object", object)
        }
        ReasonCode::UnknownPrompt if d.outcome() == Outcome::PendingUser => {
            Message::new("summary-unknown-prompt").arg("object", object)
        }
        ReasonCode::UnknownPrompt => Message::new("summary-unknown-answered").arg("object", object),
        ReasonCode::UnknownDetected => {
            Message::new("summary-unknown-detected").arg("object", object)
        }
        ReasonCode::UnknownAllowed => Message::new("summary-unknown-allowed").arg("object", object),
        ReasonCode::RestrictUnavailable => {
            Message::new("summary-restrict-unavailable").arg("object", object)
        }
        ReasonCode::SelfAllow => Message::new("summary-self-allow"),
        ReasonCode::Exclusion => Message::new("summary-excluded").arg("rule", rule),
        ReasonCode::InstanceLimit => Message::new("summary-instance-limit").arg("rule", rule),
        ReasonCode::AuditModeWouldBlock if d.would_have_been() == Outcome::PendingUser => {
            Message::new("summary-would-ask")
                .arg("mode", mode_name(d.mode()))
                .arg("object", object)
        }
        ReasonCode::OverrideSession if d.would_have_been() == Outcome::PendingUser => {
            Message::new("summary-override-ask")
                .arg("mode", mode_name(d.mode()))
                .arg("object", object)
        }
        ReasonCode::AuditModeWouldBlock | ReasonCode::OverrideSession => {
            let id = if d.outcome() == Outcome::AllowedOverride {
                "summary-override"
            } else {
                "summary-would-block"
            };
            let m = Message::new(id).arg("mode", mode_name(d.mode()));
            if rule.is_empty() {
                m.arg("cause", "implicit").arg("object", object)
            } else {
                m.arg("cause", "rule").arg("rule", rule)
            }
        }
    }
}

/// The deciding rule's context criteria that held, as a reason a person can
/// act on, such as "you are not in S-1-5-32-544". Groups are named as the
/// rule names them; directory display names arrive with the agent's
/// context collection (#4).
fn reason(trace: &Trace) -> Option<Message> {
    let d = trace.decisive.as_ref()?;
    let c = d
        .criteria
        .iter()
        .find(|c| c.field.is_context() && c.contributing && c.result == c.needed)?;
    let values = c.expected.join(", ");
    let negative = !c.operator.is_positive() != c.under_not;
    // A yes-or-no test: what the fact was, given that the test held.
    let holds_true = (c.operator == Operator::IsTrue) != c.under_not;
    let id = match (c.field, c.field.class(), negative) {
        (Field::UserGroups, _, false) => "reason-in-group",
        (Field::UserGroups, _, true) => "reason-not-in-group",
        (Field::UserIsAdmin, _, _) if holds_true => "reason-admin",
        (Field::UserIsAdmin, _, _) => "reason-not-admin",
        (_, FieldClass::Bool, _) if holds_true => "reason-flag-true",
        (_, FieldClass::Bool, _) => "reason-flag-false",
        _ => "reason-context",
    };
    Some(
        Message::new(id)
            .arg("values", values)
            .arg("field", field_name(c.field))
            .arg("operator", operator_text(c)),
    )
}

fn why_not(n: &NearMiss) -> Option<Message> {
    let c = n.failing.first()?;
    let rule = named(&n.name, &n.rule);
    let verb = match n.action {
        ActionKind::Deny => "block",
        ActionKind::Ignore => "exclude",
        ActionKind::Audit => "annotate",
        ActionKind::TrustSource => "trust",
        _ => "allow",
    };
    let base = |id: &'static str| {
        Message::new(id)
            .arg("rule", rule.clone())
            .arg("verb", verb)
            .arg("field", field_name(c.field))
            // Every other failing criterion, including those the trace
            // left out of `failing`.
            .arg(
                "more",
                (n.failing.len() + n.failing_omitted as usize)
                    .saturating_sub(1)
                    .to_string(),
            )
    };
    let expected = c.expected.join(", ");
    if c.notes.contains(&"path_acl_unsafe") {
        return Some(base("why-not-user-writable"));
    }
    if c.notes.contains(&"short_name_unresolved") {
        return Some(base("why-not-short-name"));
    }
    if c.notes.contains(&"signer_not_trusted") {
        return Some(base("why-not-signer-untrusted"));
    }
    if c.result == TriState::Unknown {
        return Some(base("why-not-unknown"));
    }
    if c.field.class() == FieldClass::Bool {
        // `is_true` and `is_false` take no values: say what was needed.
        let needed_true = (c.operator == Operator::IsTrue) != c.under_not;
        return Some(base(if needed_true {
            "why-not-flag-true"
        } else {
            "why-not-flag-false"
        }));
    }
    let observed = c.observed.as_ref();
    match observed {
        Some(o) if o.known && !o.withheld && !o.values.is_empty() => Some(
            base("why-not-mismatch")
                .arg("observed", o.values.join(", "))
                .arg("operator", operator_text(c))
                .arg("expected", expected),
        ),
        _ => Some(
            base("why-not-mismatch-withheld")
                .arg("operator", operator_text(c))
                .arg("expected", expected),
        ),
    }
}

fn operator_text(c: &CriterionTrace) -> String {
    let op = operator_name(c.operator);
    if c.under_not { format!("not {op}") } else { op }
}

fn rule_label(r: &RuleRef) -> String {
    r.display_id
        .map_or_else(|| r.rule_id.to_string(), |d| d.to_string())
}

fn named(name: &str, r: &RuleRef) -> String {
    format!("'{name}' ({})", rule_label(r))
}

const fn mode_name(m: Mode) -> &'static str {
    match m {
        Mode::Disabled => "disabled",
        Mode::Monitor => "monitor",
        Mode::Audit => "audit",
        Mode::Learning => "learning",
        Mode::Enforce => "enforce",
    }
}

const fn mode_step_name(k: ModeStepKind) -> &'static str {
    match k {
        ModeStepKind::Lockdown => "lockdown",
        ModeStepKind::DeviceMode => "device_mode",
        ModeStepKind::MandatoryDeny => "mandatory_deny",
        ModeStepKind::Disconnected => "disconnected",
        ModeStepKind::ObjectType => "object_type",
        ModeStepKind::ControlLevel => "control_level",
        ModeStepKind::RuleSetOverride => "rule_set_override",
        ModeStepKind::RuleOverride => "rule_override",
        ModeStepKind::Session => "session",
        ModeStepKind::BootPhase => "boot_phase",
        ModeStepKind::Effective => "effective",
        ModeStepKind::Applied => "applied",
    }
}

const fn stage_name(s: StageName) -> &'static str {
    match s {
        StageName::MandatoryDeny => "mandatory_deny",
        StageName::Exclusion => "exclusion",
        StageName::SessionOverride => "session_override",
        StageName::Policy => "policy",
        StageName::Attribute => "attribute",
        StageName::Unknown => "unknown",
    }
}

const fn rule_stage_name(s: RuleStage) -> &'static str {
    match s {
        RuleStage::MandatoryDeny => "mandatory_deny",
        RuleStage::Exclusion => "exclusion",
        RuleStage::Policy => "policy",
        RuleStage::Annotation => "annotation",
        RuleStage::TrustSource => "trust_source",
    }
}

fn model_name(trace: &Trace) -> String {
    match serde_json::to_value(trace.precedence_model) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

/// The message of a warning that names rules, and of one that names none.
const fn warning_id(c: WarningCode) -> (&'static str, &'static str) {
    match c {
        WarningCode::PathAclUnsafe => ("warning-path-acl-unsafe", "warning-path-acl-unsafe-alone"),
        WarningCode::ShortNameUnresolved => ("warning-short-name", "warning-short-name-alone"),
        WarningCode::ScopeStale => ("warning-scope-stale", "warning-scope-stale-alone"),
        WarningCode::ConditionTimeout => (
            "warning-condition-timeout",
            "warning-condition-timeout-alone",
        ),
        WarningCode::UserControlledContext => {
            ("warning-user-controlled", "warning-user-controlled-alone")
        }
        WarningCode::ClockUntrusted => ("warning-clock-untrusted", "warning-clock-untrusted-alone"),
        WarningCode::SignatureRelaxed => (
            "warning-signature-relaxed",
            "warning-signature-relaxed-alone",
        ),
    }
}

/// The English templates, by message ID. Every message [`explain`] builds
/// has one; a test checks that.
pub const ENGLISH: &[(&str, &str)] = &[
    (
        "why-not-flag-true",
        "Rule { $rule } would { $verb } this file, but { $field } is not true.",
    ),
    (
        "why-not-flag-false",
        "Rule { $rule } would { $verb } this file, but { $field } is not false.",
    ),
    ("warning-detail", "Detail: { $detail }."),
    (
        "warning-path-acl-unsafe-alone",
        "Warning: a path rule did not count, because users may be able to write the path.",
    ),
    (
        "warning-short-name-alone",
        "Warning: the path has a short name that could not be expanded.",
    ),
    (
        "warning-scope-stale-alone",
        "Warning: the group membership used by a scope is stale.",
    ),
    (
        "warning-condition-timeout-alone",
        "Warning: a condition ran out of time.",
    ),
    (
        "warning-user-controlled-alone",
        "Warning: a rule read context the user controls.",
    ),
    (
        "warning-clock-untrusted-alone",
        "Warning: the device clock is not trusted.",
    ),
    (
        "warning-signature-relaxed-alone",
        "Warning: a signature was accepted only because a certificate option relaxed a check.",
    ),
    (
        "summary-disabled",
        "Protection is disabled on this device: nothing was decided.",
    ),
    ("summary-allowed", "Allowed by rule { $rule }."),
    ("summary-blocked", "Blocked by rule { $rule }."),
    (
        "summary-instance-limit",
        "Blocked: rule { $rule } allows only a limited number of copies per session, and that many are already running.",
    ),
    (
        "summary-mandatory",
        "Blocked by mandatory rule { $rule }. Nothing can override it.",
    ),
    (
        "summary-implicit",
        "Blocked: no rule allows this { $object }.",
    ),
    (
        "summary-unknown-restricted",
        "Allowed in containment: no rule decides this { $object }, and unknown objects here are restricted.",
    ),
    (
        "summary-unknown-prompt",
        "Waiting for you: no rule decides this { $object }, so you are asked whether it may run.",
    ),
    (
        "summary-unknown-answered",
        "Decided by the answer to a prompt: no rule decides this { $object }.",
    ),
    (
        "summary-unknown-detected",
        "Allowed and reported: no rule decides this { $object }, and unknown objects here are detected.",
    ),
    (
        "summary-unknown-allowed",
        "Allowed: no rule decides this { $object }, and unknown objects here are allowed.",
    ),
    (
        "summary-restrict-unavailable",
        "Blocked: no rule decides this { $object }, and it could not be contained on this device.",
    ),
    (
        "summary-override-ask",
        "Allowed by an override session in { $mode } mode. Without it you would be asked whether this { $object } may run.",
    ),
    (
        "summary-would-ask",
        "Allowed in { $mode } mode. In enforce mode you would be asked whether this { $object } may run.",
    ),
    (
        "summary-self-allow",
        "Allowed: this is one of Palisade's own files.",
    ),
    (
        "summary-excluded",
        "Excluded by rule { $rule }: not evaluated further.",
    ),
    (
        "summary-would-block-rule",
        "Allowed in { $mode } mode. In enforce mode, rule { $rule } would block it.",
    ),
    (
        "summary-would-block-implicit",
        "Allowed in { $mode } mode. In enforce mode it would be blocked: no rule allows this { $object }.",
    ),
    (
        "summary-override-rule",
        "Allowed by an override session. Otherwise rule { $rule } would block it.",
    ),
    (
        "summary-override-implicit",
        "Allowed by an override session. Otherwise it would be blocked: no rule allows this { $object }.",
    ),
    ("reason-in-group", "you are in { $values }"),
    ("reason-not-in-group", "you are not in { $values }"),
    ("reason-admin", "you are an administrator"),
    ("reason-not-admin", "you are not an administrator"),
    ("reason-context", "{ $field } { $operator } { $values }"),
    ("reason-flag-true", "{ $field } is true"),
    ("reason-flag-false", "{ $field } is false"),
    (
        "tray-with-reason",
        "{ $summary } This is because { $reason }.",
    ),
    ("mode", "Effective mode: { $mode }."),
    ("mode-step", "Mode step { $step }: { $mode }."),
    (
        "mode-step-detail",
        "Mode step { $step }: { $mode } ({ $detail }).",
    ),
    (
        "stage",
        "Decided at stage { $stage }, under the { $model } precedence model.",
    ),
    (
        "overridden",
        "Other matching rules overridden by the deciding rule: { $count }.",
    ),
    (
        "unknown-out-of-scope",
        "The policy's scope does not cover this user, device or session, or a fact it needs is unknown, so its unknown-application settings do not apply: the built-in implicit deny decides.",
    ),
    (
        "unknown-allow",
        "The { $field } fact was unknown, so a rule that would let this run did not apply.",
    ),
    (
        "unknown-deny",
        "The { $field } fact was unknown, so a deny rule did not apply.",
    ),
    (
        "unknown-deny-closed",
        "The { $field } fact was unknown, and a deny rule that fails closed applied.",
    ),
    (
        "unknown-audit",
        "The { $field } fact was unknown, so an audit rule did not annotate.",
    ),
    (
        "warning-path-acl-unsafe",
        "Warning: a path rule did not count, because users may be able to write the path: { $rules }.",
    ),
    (
        "warning-short-name",
        "Warning: the path has a short name that could not be expanded: { $rules }.",
    ),
    (
        "warning-scope-stale",
        "Warning: the group membership used by a scope is stale: { $rules }.",
    ),
    (
        "warning-condition-timeout",
        "Warning: a condition ran out of time: { $rules }.",
    ),
    (
        "warning-user-controlled",
        "Warning: a rule read context the user controls: { $rules }.",
    ),
    (
        "warning-clock-untrusted",
        "Warning: the device clock is not trusted: { $rules }.",
    ),
    (
        "warning-signature-relaxed",
        "Warning: a signature was accepted only because a certificate option relaxed a check: { $rules }.",
    ),
    (
        "inactive",
        "Rule { $rule } would have matched ({ $action }), but it is disabled.",
    ),
    (
        "scope-rejected",
        "Rule { $rule } matched this file, but its { $level } scope does not cover this case ({ $dimension }), so it did not apply.",
    ),
    (
        "why-not-mismatch",
        "Rule { $rule } would { $verb } this file, but the { $field } on this file is `{ $observed }` (expected { $operator } `{ $expected }`).",
    ),
    (
        "why-not-mismatch-withheld",
        "Rule { $rule } would { $verb } this file, but the { $field } does not match (expected { $operator } `{ $expected }`).",
    ),
    (
        "why-not-unknown",
        "Rule { $rule } would { $verb } this file, but the { $field } is unknown.",
    ),
    (
        "why-not-user-writable",
        "Rule { $rule } would { $verb } this file, but the path is user-writable.",
    ),
    (
        "why-not-short-name",
        "Rule { $rule } would { $verb } this file, but the path has a short name that could not be expanded.",
    ),
    (
        "why-not-signer-untrusted",
        "Rule { $rule } would { $verb } this file, but its signature is not trusted.",
    ),
    (
        "why-not-more",
        "{ $more } more criteria of that rule also failed.",
    ),
    (
        "suggest-hash",
        "Draft: a rule allowing this exact file by its hash.",
    ),
    (
        "suggest-publisher-product-version",
        "Draft: a rule allowing this publisher, product and version or later.",
    ),
    (
        "suggest-publisher-product",
        "Draft: a rule allowing this publisher and product.",
    ),
    (
        "suggest-publisher",
        "Draft: a rule allowing this publisher.",
    ),
    (
        "suggest-path",
        "Draft: a rule allowing this path, which users cannot write.",
    ),
    (
        "suggest-effect-allow",
        "Added to the policy, it would allow this file.",
    ),
    (
        "suggest-effect-mandatory",
        "A mandatory rule blocks this file, so no allow rule can change that.",
    ),
    (
        "suggest-effect-deny-wins",
        "A deny rule also matches, and under deny_wins a deny beats every allow, so no allow rule can stop it blocking this file in enforce mode.",
    ),
    (
        "suggest-effect-deny",
        "Added to the policy, it may allow this file, but a deny rule also matches and the precedence model may still block it.",
    ),
    ("heading-why-not", "Why not allowed?"),
    ("heading-suggestion", "What would allow this?"),
    ("heading-rules", "Matching rules"),
    ("column-rule", "Rule"),
    ("column-name", "Name"),
    ("column-action", "Action"),
    ("column-stage", "Stage"),
    ("column-role", "Role"),
];

/// Message templates, by ID.
#[derive(Clone, Debug)]
pub struct Catalog {
    templates: BTreeMap<String, String>,
}

/// A translation file could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogError {
    /// The 1-based line.
    pub line: usize,
    /// What is wrong.
    pub message: &'static str,
}

impl core::fmt::Display for CatalogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for CatalogError {}

impl Catalog {
    /// The built-in English templates.
    #[must_use]
    pub fn english() -> Self {
        Self {
            templates: ENGLISH
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    /// English, overlaid with a translation in the Fluent subset: one
    /// `id = text` per line, blank lines and `#` comments. Only IDs that
    /// English has are accepted, so a typo is an error rather than a
    /// message that never shows.
    ///
    /// # Errors
    ///
    /// Returns the first line that is not a comment, blank, or `id = text`
    /// with a known ID.
    pub fn with_translation(ftl: &str) -> Result<Self, CatalogError> {
        let mut c = Self::english();
        for (i, line) in ftl.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((id, text)) = line.split_once('=') else {
                return Err(CatalogError {
                    line: i + 1,
                    message: "expected `id = text`",
                });
            };
            let id = id.trim();
            if !c.templates.contains_key(id) {
                return Err(CatalogError {
                    line: i + 1,
                    message: "unknown message ID",
                });
            }
            c.templates.insert(id.to_owned(), text.trim().to_owned());
        }
        Ok(c)
    }

    /// Renders one message as plain text. A placeholder whose argument is
    /// missing is left as it is; an unknown ID renders as the ID. Control
    /// characters in arguments become spaces, so a value cannot add lines.
    #[must_use]
    pub fn format(&self, m: &Message) -> String {
        self.styled(m, Style::Plain)
    }

    /// Renders one message as Markdown: the template's text is kept, and
    /// each argument is escaped, so text from a policy or a file cannot add
    /// markup or links. An argument inside a code span (backticks in the
    /// template) is fenced with enough backticks to hold it.
    #[must_use]
    pub fn format_markdown(&self, m: &Message) -> String {
        self.styled(m, Style::Markdown)
    }

    fn styled(&self, m: &Message, style: Style) -> String {
        let id = match (m.id, m.args.get("cause").map(String::as_str)) {
            ("summary-would-block", Some("implicit")) => "summary-would-block-implicit",
            ("summary-would-block", _) => "summary-would-block-rule",
            ("summary-override", Some("implicit")) => "summary-override-implicit",
            ("summary-override", _) => "summary-override-rule",
            (id, _) => id,
        };
        let Some(t) = self.templates.get(id) else {
            return id.to_owned();
        };
        fill(t, &m.args, style)
    }

    fn text(&self, id: &'static str) -> String {
        self.format(&Message::new(id))
    }

    fn text_markdown(&self, id: &'static str) -> String {
        self.format_markdown(&Message::new(id))
    }
}

impl Default for Catalog {
    fn default() -> Self {
        Self::english()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Style {
    Plain,
    Markdown,
}

/// Replaces each `{ $name }` (spaces optional) with its argument.
fn fill(template: &str, args: &BTreeMap<&'static str, String>, style: Style) -> String {
    let mut out = String::with_capacity(template.len());
    let mut in_code = false;
    let mut chars = template.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            '`' => {
                in_code = !in_code;
                // In Markdown the fence comes with the argument.
                if style == Style::Plain {
                    out.push('`');
                }
            }
            '{' => {
                let rest = &template[i + 1..];
                let parsed = rest.find('}').and_then(|end| {
                    let name = rest[..end].trim().strip_prefix('$')?.trim();
                    Some((end, args.get(name)?))
                });
                match parsed {
                    Some((end, value)) => {
                        let value = flat(value);
                        out.push_str(&match (style, in_code) {
                            (Style::Plain, _) => value,
                            (Style::Markdown, true) => md_code(&value),
                            (Style::Markdown, false) => md(&value),
                        });
                        // Skip past the closing brace.
                        while chars.peek().is_some_and(|(j, _)| *j <= i + 1 + end) {
                            chars.next();
                        }
                    }
                    None => out.push('{'),
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// A value with control characters replaced by spaces.
fn flat(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// A Markdown code span holding `value` literally: fenced with one more
/// backtick than its longest run, and padded if it starts or ends with one.
fn md_code(value: &str) -> String {
    let mut longest = 0;
    let mut run = 0;
    for c in value.chars() {
        run = if c == '`' { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    let fence = "`".repeat(longest + 1);
    let pad = if value.starts_with('`') || value.ends_with('`') || value.is_empty() {
        " "
    } else {
        ""
    };
    format!("{fence}{pad}{value}{pad}{fence}")
}

/// The whole document as plain text, for the CLI.
#[must_use]
pub fn render_text(doc: &ExplainDoc, catalog: &Catalog) -> String {
    let mut out = String::new();
    out.push_str(&catalog.format(&doc.summary));
    out.push('\n');
    if let Some(r) = &doc.reason {
        out.push_str(&format!("  ({})\n", catalog.format(r)));
    }
    for p in &doc.paragraphs {
        out.push_str(&catalog.format(p));
        out.push('\n');
    }
    if !doc.why_not.is_empty() {
        out.push('\n');
        out.push_str(&catalog.text("heading-why-not"));
        out.push('\n');
        for m in &doc.why_not {
            out.push_str("- ");
            out.push_str(&why_not_text(m, catalog, Style::Plain));
            out.push('\n');
        }
    }
    if let Some(s) = &doc.suggestion {
        out.push('\n');
        out.push_str(&catalog.text("heading-suggestion"));
        out.push('\n');
        out.push_str(&suggestion_text(s, catalog, Style::Plain));
        out.push('\n');
    }
    if !doc.table.is_empty() {
        out.push('\n');
        out.push_str(&catalog.text("heading-rules"));
        out.push('\n');
        let header = [
            catalog.text("column-rule"),
            catalog.text("column-name"),
            catalog.text("column-action"),
            catalog.text("column-stage"),
            catalog.text("column-role"),
        ];
        let rows: Vec<[String; 5]> = doc
            .table
            .iter()
            .map(|r| {
                [
                    flat(&r.rule),
                    flat(&r.name),
                    r.action.to_owned(),
                    r.stage.to_owned(),
                    r.role.to_owned(),
                ]
            })
            .collect();
        let mut widths = header.clone().map(|h| h.chars().count());
        for r in &rows {
            for (w, c) in widths.iter_mut().zip(r) {
                *w = (*w).max(c.chars().count());
            }
        }
        for r in std::iter::once(&header).chain(&rows) {
            let cells: Vec<String> = r
                .iter()
                .zip(widths)
                .map(|(c, w)| format!("{c:<w$}"))
                .collect();
            out.push_str(cells.join("  ").trim_end());
            out.push('\n');
        }
    }
    out
}

/// The whole document as Markdown, for the console. Text from the policy
/// and the facts (rule names, values) is escaped, so it cannot add links or
/// markup.
#[must_use]
pub fn render_markdown(doc: &ExplainDoc, catalog: &Catalog) -> String {
    let mut out = String::new();
    out.push_str("**");
    out.push_str(&catalog.format_markdown(&doc.summary));
    out.push_str("**\n");
    if let Some(r) = &doc.reason {
        out.push_str(&format!("\n_{}_\n", catalog.format_markdown(r)));
    }
    if !doc.paragraphs.is_empty() {
        out.push('\n');
        for p in &doc.paragraphs {
            out.push_str(&catalog.format_markdown(p));
            out.push_str("\n\n");
        }
        out.pop();
    }
    if !doc.why_not.is_empty() {
        out.push_str(&format!(
            "\n### {}\n\n",
            catalog.text_markdown("heading-why-not")
        ));
        for m in &doc.why_not {
            out.push_str(&format!(
                "- {}\n",
                why_not_text(m, catalog, Style::Markdown)
            ));
        }
    }
    if let Some(s) = &doc.suggestion {
        out.push_str(&format!(
            "\n### {}\n\n{}\n",
            catalog.text_markdown("heading-suggestion"),
            suggestion_text(s, catalog, Style::Markdown)
        ));
    }
    if !doc.table.is_empty() {
        out.push_str(&format!(
            "\n### {}\n\n",
            catalog.text_markdown("heading-rules")
        ));
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n|---|---|---|---|---|\n",
            catalog.text_markdown("column-rule"),
            catalog.text_markdown("column-name"),
            catalog.text_markdown("column-action"),
            catalog.text_markdown("column-stage"),
            catalog.text_markdown("column-role"),
        ));
        for r in &doc.table {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                md(&flat(&r.rule)),
                md(&flat(&r.name)),
                r.action,
                r.stage,
                r.role
            ));
        }
    }
    out
}

/// One short sentence, for a tray notification: the summary, and the
/// reason if there is one. For example: "Blocked by rule 'Block script
/// hosts for standard users' (R-000412). This is because you are not in
/// S-1-5-32-544."
#[must_use]
pub fn render_tray(doc: &ExplainDoc, catalog: &Catalog) -> String {
    let summary = catalog.format(&doc.summary);
    match &doc.reason {
        Some(r) => catalog.format(
            &Message::new("tray-with-reason")
                .arg("summary", summary)
                .arg("reason", catalog.format(r)),
        ),
        None => summary,
    }
}

fn why_not_text(m: &Message, catalog: &Catalog, style: Style) -> String {
    let mut s = catalog.styled(m, style);
    if m.args.get("more").is_some_and(|n| n != "0") {
        s.push(' ');
        s.push_str(&catalog.styled(
            &Message {
                id: "why-not-more",
                args: m.args.clone(),
            },
            style,
        ));
    }
    s
}

fn suggestion_text(m: &Message, catalog: &Catalog, style: Style) -> String {
    let mut s = catalog.styled(m, style);
    let effect = match m.args.get("effect").map(String::as_str) {
        Some("allow") => Some("suggest-effect-allow"),
        Some("mandatory") => Some("suggest-effect-mandatory"),
        Some("deny_wins") => Some("suggest-effect-deny-wins"),
        Some("deny") => Some("suggest-effect-deny"),
        _ => None,
    };
    if let Some(id) = effect {
        s.push(' ');
        s.push_str(&catalog.styled(&Message::new(id), style));
    }
    s
}

/// Escapes Markdown punctuation and HTML, so text renders literally.
fn md(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' | '`' | '*' | '_' | '{' | '}' | '[' | ']' | '(' | ')' | '#' | '+' | '-' | '!'
            | '|' | '~' | '>' => {
                out.push('\\');
                out.push(c);
            }
            '<' => out.push_str("&lt;"),
            '&' => out.push_str("&amp;"),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}
