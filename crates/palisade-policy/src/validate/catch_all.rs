//! Validation of catch-all rules (#33, #35, #329).
//!
//! A `catch_all` rule is the default of a policy: the only rule that may
//! have no identity anchor, and a floor at stage 4 that decides only when no
//! other rule matched ([`crate::evaluate`]). Because it can match every
//! object, it is held to stricter rules than any other:
//!
//! - its name starts with `Default` or contains `Catch-all`, so it is
//!   recognisable wherever it is listed;
//! - it allows or denies (`allow`, `allow_contained`, `allow_elevated` or
//!   `deny`): a default that only audits, trusts, excludes or defers decides
//!   nothing;
//! - it is not in a mandatory rule set, whose rules must identify what they
//!   block;
//! - a rule set holds at most one;
//! - one that lets objects run needs the policy's `confirm_permit_all: "I
//!   UNDERSTAND"`, and is never allowed under a compliance preset, which
//!   requires default deny (ISM-1870);
//! - under `first_match`, a policy should end with one, enabled, in a rule
//!   set it references (`catch_all_missing`). This is a warning, not an
//!   error: without a catch-all, an object no rule matched goes to the
//!   unknown policy (#39), whose default blocks, so a missing one never
//!   fails open.

use std::collections::BTreeSet;

use super::{ErrorCode, Validator};
use crate::model::{CONFIRM_PERMIT_ALL, PolicyDocument, PrecedenceModel};
use crate::precedence::Verdict;

impl Validator {
    pub(super) fn catch_alls(&mut self, doc: &PolicyDocument) {
        let policy = &doc.policy;
        let referenced: BTreeSet<_> = policy.rule_sets.iter().collect();
        let confirmed = policy.confirm_permit_all.as_deref() == Some(CONFIRM_PERMIT_ALL);
        if let Some(text) = policy
            .confirm_permit_all
            .as_deref()
            .filter(|t| *t != CONFIRM_PERMIT_ALL)
        {
            self.push(
                ErrorCode::PermitAllUnconfirmed,
                "/policy/confirm_permit_all",
                format!("`{text}` does not confirm; write exactly `{CONFIRM_PERMIT_ALL}`"),
            );
        }
        let mut found = false;
        for (i, set) in doc.rule_sets.iter().enumerate() {
            for (j, rule) in set.rules.iter().enumerate().filter(|(_, r)| r.attribute) {
                self.attribute_rule(&format!("/rule_sets/{i}/rules/{j}"), set, rule);
            }
            let mut first: Option<usize> = None;
            for (j, rule) in set.rules.iter().enumerate() {
                if !rule.catch_all {
                    continue;
                }
                let path = format!("/rule_sets/{i}/rules/{j}");
                if !rule.has_catch_all_name() {
                    self.push(
                        ErrorCode::InvalidCatchAll,
                        &format!("{path}/name"),
                        "a catch-all rule's name starts with `Default` or contains `Catch-all`",
                    );
                }
                let verdict = Verdict::of(&rule.action);
                if verdict.is_none() {
                    self.push(
                        ErrorCode::InvalidCatchAll,
                        &format!("{path}/action"),
                        format!(
                            "a catch-all rule allows or denies; `{}` decides nothing",
                            rule.action.kind()
                        ),
                    );
                }
                if set.mandatory {
                    self.push(
                        ErrorCode::InvalidCatchAll,
                        &format!("{path}/catch_all"),
                        "a mandatory rule set blocks only what its rules identify; it cannot hold a catch-all",
                    );
                }
                match first {
                    Some(k) => self.push(
                        ErrorCode::InvalidCatchAll,
                        &format!("{path}/catch_all"),
                        format!(
                            "rule set {} already has a catch-all, /rule_sets/{i}/rules/{k}",
                            set.id
                        ),
                    ),
                    None => first = Some(j),
                }
                if verdict.is_some_and(Verdict::allows) {
                    if !confirmed {
                        self.push(
                            ErrorCode::PermitAllUnconfirmed,
                            &format!("{path}/action"),
                            format!(
                                "this catch-all lets every object no other rule matched run; set the policy's `confirm_permit_all` to `{CONFIRM_PERMIT_ALL}` if that is intended"
                            ),
                        );
                    }
                    if let Some(preset) = policy.unknown.preset {
                        self.push(
                            ErrorCode::UnknownAllowNotPermitted,
                            &format!("{path}/action"),
                            format!(
                                "under the `{}` preset a catch-all cannot let objects run: Essential Eight requires default deny (ISM-1870)",
                                preset.as_str()
                            ),
                        );
                    }
                }
                found |= rule.enabled
                    && verdict.is_some()
                    && !set.mandatory
                    && referenced.contains(&set.id);
            }
        }
        if policy.precedence_model == PrecedenceModel::FirstMatch && !found {
            self.push(
                ErrorCode::CatchAllMissing,
                "/policy/precedence_model",
                "a `first_match` policy ends with a catch-all rule: add an enabled rule with `catch_all: true`, named `Default…` or containing `Catch-all`, such as a deny whose match is `all: []`",
            );
        }
    }
}

impl Validator {
    /// A post-allow attribute rule (#329): it only narrows an allow, so it
    /// denies or audits, is not in a mandatory rule set and is not a
    /// catch-all.
    fn attribute_rule(
        &mut self,
        path: &str,
        set: &crate::model::RuleSet,
        rule: &crate::model::Rule,
    ) {
        use crate::model::Action;
        if !matches!(rule.action, Action::Deny(_) | Action::Audit {}) {
            self.push(
                ErrorCode::InvalidAttributeRule,
                &format!("{path}/action"),
                format!(
                    "an attribute rule only narrows an allow: it denies or audits, not `{}`",
                    rule.action.kind()
                ),
            );
        }
        if set.mandatory {
            self.push(
                ErrorCode::InvalidAttributeRule,
                &format!("{path}/attribute"),
                "a mandatory rule set blocks before any allow; it cannot hold an attribute rule",
            );
        }
        if rule.catch_all {
            self.push(
                ErrorCode::InvalidAttributeRule,
                &format!("{path}/attribute"),
                "a rule is a catch-all or an attribute rule, not both",
            );
        }
    }
}

#[cfg(test)]
mod probe_tests;
#[cfg(test)]
mod tests;
