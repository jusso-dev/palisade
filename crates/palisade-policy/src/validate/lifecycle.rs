//! Validation of rule lifecycle and governance (#40).

use std::collections::BTreeSet;

use super::{ErrorCode, Validator};
use crate::lifecycle::{is_exception, needs_review, review_by};
use crate::model::lifecycle::limits::{
    COUNTER_REPORT_HOURS, EXPIRING_SOON_DAYS, MAX_EXCEPTION_DAYS, MAX_EXPIRY_NOTICE_DAYS,
    MAX_EXPIRY_NOTICES, STALE_AFTER_DAYS,
};
use crate::model::{ActionKind, FindingSeverity, OnExpire, PolicyDocument, Rule, RuleSet};
use crate::unknown::baseline::SYSTEM_BASELINE_ID;

impl Validator {
    pub(super) fn lifecycle(&mut self, doc: &PolicyDocument) {
        let g = &doc.policy.governance;
        let base = "/policy/governance";
        for (key, value, range) in [
            ("stale_after_days", g.stale_after_days, STALE_AFTER_DAYS),
            (
                "expiring_soon_days",
                g.expiring_soon_days,
                EXPIRING_SOON_DAYS,
            ),
            (
                "counter_report_hours",
                g.counter_report_hours,
                COUNTER_REPORT_HOURS,
            ),
        ] {
            if !range.contains(&value) {
                self.push(
                    ErrorCode::InvalidGovernance,
                    &format!("{base}/{key}"),
                    format!("{value} is outside {}..={}", range.start(), range.end()),
                );
            }
        }
        if g.expiry_notice_days.len() > MAX_EXPIRY_NOTICES {
            self.push(
                ErrorCode::InvalidGovernance,
                &format!("{base}/expiry_notice_days"),
                format!("at most {MAX_EXPIRY_NOTICES} notices"),
            );
        }
        let mut seen = BTreeSet::new();
        for (i, d) in g.expiry_notice_days.iter().enumerate() {
            if *d > MAX_EXPIRY_NOTICE_DAYS || !seen.insert(*d) {
                self.push(
                    ErrorCode::InvalidGovernance,
                    &format!("{base}/expiry_notice_days/{i}"),
                    format!(
                        "each notice is 0 to {MAX_EXPIRY_NOTICE_DAYS} days before expiry, once"
                    ),
                );
            }
        }
        for (key, severity) in &g.severity {
            let path = format!("{base}/severity/{}", super::pointer_token(key));
            match crate::analysis::FindingCode::from_name(key) {
                None => self.push(
                    ErrorCode::InvalidGovernance,
                    &path,
                    format!("`{key}` is not a finding code"),
                ),
                // A policy may raise a severity, never lower it: lowering
                // an `error` would let the policy's own author pass the
                // publish gate without an administrator's override (#40).
                Some(code) if *severity < code.default_severity() => self.push(
                    ErrorCode::InvalidGovernance,
                    &path,
                    format!(
                        "`{key}` is `{}` by default; a policy may raise a finding's severity but not lower it (a tenant administrator overrides findings at publishing)",
                        severity_name(code.default_severity())
                    ),
                ),
                Some(_) => {}
            }
        }

        for (i, set) in doc.rule_sets.iter().enumerate() {
            if set.id.to_string() == SYSTEM_BASELINE_ID {
                self.push(
                    ErrorCode::ReservedRuleSetId,
                    &format!("/rule_sets/{i}/id"),
                    format!(
                        "`{SYSTEM_BASELINE_ID}` is the managed `system_baseline`; the engine adds it after validation (`ValidatedPolicy::with_system_baseline`), so a policy document cannot contain a rule set with this ID"
                    ),
                );
            }
            for (j, rule) in set.rules.iter().enumerate() {
                let path = format!("/rule_sets/{i}/rules/{j}");
                if let (Some(a), Some(e)) = (rule.activates_at, rule.expires_at)
                    && e <= a
                {
                    self.push(
                        ErrorCode::InvalidActivityWindow,
                        &format!("{path}/expires_at"),
                        format!("`expires_at` ({e}) must be after `activates_at` ({a})"),
                    );
                }
                if rule.on_expire != OnExpire::Deactivate && rule.expires_at.is_none() {
                    self.push(
                        ErrorCode::OnExpireNotApplicable,
                        &format!("{path}/on_expire"),
                        "`on_expire` needs `expires_at`",
                    );
                } else if rule.on_expire == OnExpire::ConvertToAudit && set.mandatory {
                    self.push(
                        ErrorCode::OnExpireNotApplicable,
                        &format!("{path}/on_expire"),
                        "a mandatory rule set holds only denies; an expired mandatory rule is removed, not converted",
                    );
                }
                if let OnExpire::DeleteAfterDays(d) = rule.on_expire
                    && !(1..=3650).contains(&d)
                {
                    self.push(
                        ErrorCode::OnExpireNotApplicable,
                        &format!("{path}/on_expire/delete_after_days"),
                        format!("{d} is outside 1..=3650"),
                    );
                }
                for (code, suffix, message) in governance_problems(doc, set, rule) {
                    self.push(code, &format!("{path}{suffix}"), message);
                }
            }
        }
    }
}

const fn severity_name(s: FindingSeverity) -> &'static str {
    match s {
        FindingSeverity::Info => "info",
        FindingSeverity::Warning => "warning",
        FindingSeverity::Error => "error",
    }
}

/// Whether governance mode is on for `doc`: `require_justification`, or
/// unset, on exactly when the policy has a compliance preset.
pub(crate) fn governance_mode(doc: &PolicyDocument) -> bool {
    doc.policy
        .governance
        .mode(doc.policy.unknown.preset.is_some())
}

/// What governance mode finds wrong with `rule` of `set` in `doc`: each
/// problem's code, its path below the rule (empty for the rule itself)
/// and a message. Empty when governance mode is off, the rule is disabled,
/// or the set is not referenced. No rule set is exempt: `read_only` is a
/// curated set's precedence flag that an author can set, and the managed
/// `system_baseline` never reaches validation (it is added afterwards,
/// [`crate::validate::ValidatedPolicy::with_system_baseline`]).
pub(crate) fn governance_problems(
    doc: &PolicyDocument,
    set: &RuleSet,
    rule: &Rule,
) -> Vec<(ErrorCode, &'static str, String)> {
    let mut out = Vec::new();
    if !governance_mode(doc) || !rule.enabled || !doc.policy.rule_sets.contains(&set.id) {
        return out;
    }
    let kind = rule.action.kind();
    let m = &rule.metadata;
    let exception = is_exception(rule);
    let needs_justification =
        kind.permits() || matches!(kind, ActionKind::TrustSource | ActionKind::Ignore) || exception;
    if needs_justification
        && m.justification
            .as_deref()
            .is_none_or(|j| j.trim().is_empty())
    {
        out.push((
            ErrorCode::JustificationRequired,
            "/metadata/justification",
            format!("governance mode needs a justification for this `{kind}` rule"),
        ));
    }
    if needs_review(kind) && review_by(m, Some(kind)).is_none() {
        out.push((
            ErrorCode::ReviewDateRequired,
            "/metadata/review_by",
            "governance mode needs `review_by`, or `created_at` to derive it (a year later)"
                .to_owned(),
        ));
    }
    if exception {
        let mut missing = Vec::new();
        match (rule.expires_at, crate::lifecycle::exception_start(m)) {
            (None, None) => missing.extend(["`expires_at`", "`approved_at`"]),
            (None, Some(_)) => missing.push("`expires_at`"),
            (Some(_), None) => missing.push("`approved_at`, to bound the expiry"),
            (Some(e), Some(start)) => {
                if start.plus_days(MAX_EXCEPTION_DAYS).is_none_or(|l| e > l) {
                    missing.push("`expires_at` at most 365 days after `approved_at`");
                }
            }
        }
        if m.approved_by.is_none() {
            missing.push("`approved_by`");
        }
        if m.risk_rating.is_none() {
            missing.push("`risk_rating`");
        }
        if !missing.is_empty() {
            out.push((
                ErrorCode::ExceptionIncomplete,
                "",
                format!(
                    "this rule is an exception (an exclusion, an allow on a weak or path identity, or `metadata.exception`); governance mode needs {}",
                    missing.join(", ")
                ),
            ));
        }
    }
    out
}
