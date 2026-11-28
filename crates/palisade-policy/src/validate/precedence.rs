//! Validation of the precedence model's inputs (#35): the options the
//! selected model uses, and each rule's `order` and `priority`.

use std::collections::{BTreeMap, BTreeSet};

use super::{ErrorCode, Validator};
use crate::model::{PolicyDocument, PrecedenceModel, PrecedenceOptions};
use crate::precedence::Verdict;

/// Reserved `order` ranges for the `first_match` model (#35). Only rules of
/// custom rule sets are checked: curated (read-only) rule sets may use the
/// curated range, and the system and catch-all ranges are for rules
/// Palisade adds itself.
pub mod order_ranges {
    use core::ops::RangeInclusive;

    /// Built-in system rules.
    pub const SYSTEM: RangeInclusive<u32> = 0..=99;
    /// Curated, read-only rule sets.
    pub const CURATED: RangeInclusive<u32> = 100..=100_000;
    /// Custom rules.
    pub const CUSTOM: RangeInclusive<u32> = 100_001..=999_989;
    /// Defaults and catch-all rules.
    pub const CATCH_ALL: RangeInclusive<u32> = 999_990..=1_000_000;
}

impl Validator {
    pub(super) fn precedence(&mut self, doc: &PolicyDocument) {
        let policy = &doc.policy;
        let model = policy.precedence_model;
        self.unused_options(model, &policy.precedence_options);

        // Only the rules of referenced rule sets are ever evaluated.
        let referenced: BTreeSet<_> = policy.rule_sets.iter().collect();
        // Priority -> (path, verdict) of the first rule seen with it.
        let mut priorities: BTreeMap<i32, (String, Verdict)> = BTreeMap::new();
        for (i, set) in doc.rule_sets.iter().enumerate() {
            for (j, rule) in set.rules.iter().enumerate() {
                let path = format!("/rule_sets/{i}/rules/{j}");
                // The schema's limit, checked for every rule set.
                if let Some(order) = rule.order.filter(|o| o > order_ranges::CATCH_ALL.end()) {
                    self.push(
                        ErrorCode::OrderOutOfRange,
                        &format!("{path}/order"),
                        format!(
                            "order {order} is above the largest order, {}",
                            order_ranges::CATCH_ALL.end()
                        ),
                    );
                }
                if !referenced.contains(&set.id) {
                    continue;
                }
                // Under `first_match`, every rule of a custom rule set that
                // has an order must use the custom range, whatever its
                // action: a `defer` or `audit` rule is placed in the same
                // order. Mandatory rule sets are decided before any order.
                if model == PrecedenceModel::FirstMatch
                    && !set.read_only
                    && !set.mandatory
                    && let Some(order) = rule.order.filter(|o| {
                        !order_ranges::CUSTOM.contains(o)
                            // A catch-all may also use the catch-all range
                            // (#329).
                            && !(rule.catch_all && order_ranges::CATCH_ALL.contains(o))
                            && o <= order_ranges::CATCH_ALL.end()
                    })
                {
                    self.push(
                        ErrorCode::OrderReserved,
                        &format!("{path}/order"),
                        format!(
                            "order {order} is reserved; rules of custom rule sets use {} to {}, and catch-all rules also {} to {}",
                            order_ranges::CUSTOM.start(),
                            order_ranges::CUSTOM.end(),
                            order_ranges::CATCH_ALL.start(),
                            order_ranges::CATCH_ALL.end()
                        ),
                    );
                }
                // Mandatory and exclusion rules are decided before the
                // model, and the other non-terminal rules never decide.
                let Some(verdict) = Verdict::of(&rule.action).filter(|_| !set.mandatory) else {
                    continue;
                };
                match model {
                    PrecedenceModel::FirstMatch => {
                        if rule.order.is_none() {
                            self.push(
                                ErrorCode::OrderRequired,
                                &format!("{path}/action"),
                                "under `first_match`, every rule that allows or denies needs an `order`",
                            );
                        }
                    }
                    PrecedenceModel::Priority => match rule.priority {
                        None => self.push(
                            ErrorCode::PriorityRequired,
                            &format!("{path}/action"),
                            "under `priority`, every rule that allows or denies needs a `priority`",
                        ),
                        Some(p) => match priorities.get(&p) {
                            Some((first, v)) if v.kind() != verdict.kind() => self.push(
                                ErrorCode::DuplicatePriority,
                                &format!("{path}/priority"),
                                format!(
                                    "priority {p} is also used by {first}, whose action is `{}`; between them the fixed action order decides",
                                    v.kind()
                                ),
                            ),
                            Some(_) => {}
                            None => {
                                priorities.insert(p, (path, verdict));
                            }
                        },
                    },
                    PrecedenceModel::DenyWins
                    | PrecedenceModel::AllowWins
                    | PrecedenceModel::Specificity => {}
                }
            }
        }
    }

    /// Warns about each option that differs from its default but that the
    /// selected model does not read.
    fn unused_options(&mut self, model: PrecedenceModel, o: &PrecedenceOptions) {
        use PrecedenceModel as M;
        let d = PrecedenceOptions::default();
        let options = [
            (
                "allow_tiebreak",
                o.allow_tiebreak != d.allow_tiebreak,
                matches!(model, M::DenyWins | M::AllowWins | M::Specificity),
            ),
            (
                "granularity_tiebreak",
                o.granularity_tiebreak != d.granularity_tiebreak,
                model == M::AllowWins,
            ),
            (
                "curated_first",
                o.curated_first != d.curated_first,
                model == M::FirstMatch,
            ),
            (
                "same_tier_tiebreak",
                o.same_tier_tiebreak != d.same_tier_tiebreak,
                model == M::Specificity,
            ),
            (
                "priority_direction",
                o.priority_direction != d.priority_direction,
                model == M::Priority,
            ),
        ];
        for (name, set, used) in options {
            if set && !used {
                self.push(
                    ErrorCode::PrecedenceOptionUnused,
                    &format!("/policy/precedence_options/{name}"),
                    format!(
                        "`{name}` has no effect under `{}`",
                        super::serde_name(&model)
                    ),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests;
