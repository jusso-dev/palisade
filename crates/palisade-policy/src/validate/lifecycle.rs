//! Validation of rule lifecycle and governance (#40).

use std::collections::BTreeSet;

use super::{ErrorCode, Validator};
use crate::lifecycle::{is_exception, needs_review, review_by};
use crate::model::lifecycle::limits::{
    COUNTER_REPORT_HOURS, EXPIRING_SOON_DAYS, MAX_EXCEPTION_DAYS, MAX_EXPIRY_NOTICE_DAYS,
    MAX_EXPIRY_NOTICES, STALE_AFTER_DAYS,
};
use crate::model::{ActionKind, OnExpire, PolicyDocument};

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
        for key in g.severity.keys() {
            if crate::analysis::FindingCode::from_name(key).is_none() {
                self.push(
                    ErrorCode::InvalidGovernance,
                    &format!("{base}/severity/{}", super::pointer_token(key)),
                    format!("`{key}` is not a finding code"),
                );
            }
        }

        let governance = g
            .require_justification
            .unwrap_or(doc.policy.unknown.preset.is_some());
        let referenced: BTreeSet<_> = doc.policy.rule_sets.iter().collect();
        for (i, set) in doc.rule_sets.iter().enumerate() {
            for (j, rule) in set.rules.iter().enumerate() {
                let path = format!("/rule_sets/{i}/rules/{j}");
                if let (Some(a), Some(e)) = (rule.activates_at, rule.expires_at) {
                    if e <= a {
                        self.push(
                            ErrorCode::InvalidActivityWindow,
                            &format!("{path}/expires_at"),
                            format!("`expires_at` ({e}) must be after `activates_at` ({a})"),
                        );
                    }
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
                if let OnExpire::DeleteAfterDays(d) = rule.on_expire {
                    if !(1..=3650).contains(&d) {
                        self.push(
                            ErrorCode::OnExpireNotApplicable,
                            &format!("{path}/on_expire/delete_after_days"),
                            format!("{d} is outside 1..=3650"),
                        );
                    }
                }
                // Governance mode applies to the rules a policy uses, and
                // never to managed read-only sets, which carry their own
                // provenance.
                if !governance || !rule.enabled || set.read_only || !referenced.contains(&set.id) {
                    continue;
                }
                let kind = rule.action.kind();
                let m = &rule.metadata;
                let exception = is_exception(rule);
                let needs_justification = kind.permits()
                    || matches!(kind, ActionKind::TrustSource | ActionKind::Ignore)
                    || exception;
                if needs_justification
                    && m.justification
                        .as_deref()
                        .is_none_or(|j| j.trim().is_empty())
                {
                    self.push(
                        ErrorCode::JustificationRequired,
                        &format!("{path}/metadata/justification"),
                        format!("governance mode needs a justification for this `{kind}` rule"),
                    );
                }
                if needs_review(kind) && review_by(m, Some(kind)).is_none() {
                    self.push(
                        ErrorCode::ReviewDateRequired,
                        &format!("{path}/metadata/review_by"),
                        "governance mode needs `review_by`, or `created_at` to derive it (a year later)",
                    );
                }
                if exception {
                    let mut missing = Vec::new();
                    match (rule.expires_at, crate::lifecycle::exception_start(m)) {
                        (None, _) => missing.push("`expires_at`"),
                        (Some(_), None) => missing.push(
                            "`approved_at`, `created_at` or `last_reviewed_at`, to bound the expiry",
                        ),
                        (Some(e), Some(start)) => {
                            if start.plus_days(MAX_EXCEPTION_DAYS).is_none_or(|l| e > l) {
                                missing.push(
                                    "`expires_at` at most 365 days after approval or the last review",
                                );
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
                        self.push(
                            ErrorCode::ExceptionIncomplete,
                            &path,
                            format!(
                                "this rule is an exception (an exclusion, an allow on a weak or path identity, or `metadata.exception`); governance mode needs {}",
                                missing.join(", ")
                            ),
                        );
                    }
                }
            }
        }
    }
}
