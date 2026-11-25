//! Rule lifecycle (#40): when a rule is active, which rules are
//! exceptions, review dates, expiry notices, review campaigns and bulk
//! changes. Everything here is pure: the caller supplies the time.
//!
//! # Active rules and the clock
//!
//! A rule is active when it is enabled, `activates_at` (if set) has been
//! reached, and `expires_at` (if set) has not. An inactive rule behaves
//! exactly as if it were absent: it never decides, annotates or grants
//! ([`Evaluator::at`](crate::evaluate::Evaluator::at)). The decision trace
//! (#41) reports it as inactive with [`Activity`]'s reason.
//!
//! Activity is checked against a [`RuleClock`]: the agent's trusted time
//! `now` (anchored time, ADR 0012) and its **floor**, the lower bound on
//! real time that the agent keeps in protected storage and never lowers.
//! While the agent is anchored the floor is raised to `now`, so the two
//! agree; they differ only after the clock was changed or the agent
//! restarted offline. Each rule then fails in the closed direction:
//!
//! - A rule that lets an object run, trusts it or excludes it
//!   ([`ActionKind::needs_identity`]) is active only while **both**
//!   readings are inside its window. It has expired once either reading
//!   reaches `expires_at`, and the floor never goes back, so **an expired
//!   allow never revives** after a clock rollback. It activates only once
//!   both readings reach `activates_at`, so setting the clock forwards
//!   cannot start it early.
//! - A deny, `audit` or `defer` rule is active while **either** reading is
//!   inside its window: it activates once either reaches `activates_at`,
//!   and expires only once both reach `expires_at`. Setting the clock
//!   forwards cannot end a deny early.
//!
//! With `on_expire: convert_to_audit` an expired rule becomes an `audit`
//! rule instead of absent: it records matches but never decides.
//! `delete_after_days` behaves as absent at once, and [`retire_due`] lists
//! it for deletion once the days have passed.
//!
//! # Exceptions
//!
//! An exception ([`is_exception`]) is a rule that weakens the default-deny
//! posture by its nature: an `ignore`, an allow whose path identity is in
//! a user-writable location (#31), an allow with a weak identity (file
//! name, metadata, or SHA-1 or MD5 only), or any rule with
//! `metadata.exception: true`. In governance mode an exception needs
//! `expires_at` at most 365 days after it was created (or approved),
//! `justification`, `approved_by` and `risk_rating`
//! ([`crate::validate`], `exception_*` codes).

pub mod counters;

use serde::Serialize;

use crate::decision::RuleRef;
use crate::model::lifecycle::limits::REVIEW_PERIOD_DAYS;
use crate::model::{
    Action, ActionKind, Date, Metadata, OnExpire, Policy, PolicyDocument, Rule, RuleId, RuleSet,
    RuleSetId, Timestamp,
};

pub use counters::{Counters, HitReport, RuleHits};

/// The agent's view of time for rule activity (ADR 0012).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RuleClock {
    /// The current trusted time: anchored time while the agent has it, or
    /// the wall clock otherwise. The server and tests pass real time.
    pub now: Timestamp,
    /// The lower bound on real time the agent keeps in protected storage,
    /// which never goes backwards. Pass `now` where there is none (the
    /// server, the policy assistant).
    pub floor: Timestamp,
}

impl RuleClock {
    /// A clock whose floor is `now`: for the server and for tests.
    #[must_use]
    pub const fn at(now: Timestamp) -> Self {
        Self { now, floor: now }
    }

    /// The earlier of the two readings.
    #[must_use]
    pub const fn earliest(&self) -> Timestamp {
        if self.now.0 < self.floor.0 {
            self.now
        } else {
            self.floor
        }
    }

    /// The later of the two readings.
    #[must_use]
    pub const fn latest(&self) -> Timestamp {
        if self.now.0 > self.floor.0 {
            self.now
        } else {
            self.floor
        }
    }
}

/// Whether a rule is active, and why not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Activity {
    /// Active.
    Active,
    /// `enabled: false`.
    Disabled,
    /// `activates_at` is in the future.
    NotYetActive,
    /// `expires_at` has passed.
    Expired,
}

impl Activity {
    /// Whether the rule takes part in evaluation as written.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Whether `rule` is active at `clock`.
#[must_use]
pub fn activity(rule: &Rule, clock: &RuleClock) -> Activity {
    if !rule.enabled {
        return Activity::Disabled;
    }
    // A permissive rule needs both readings inside its window; any other
    // rule needs only one.
    let (start, end) = if rule.action.kind().needs_identity() {
        (clock.earliest(), clock.latest())
    } else {
        (clock.latest(), clock.earliest())
    };
    if rule.expires_at.is_some_and(|e| e <= end) {
        return Activity::Expired;
    }
    if rule.activates_at.is_some_and(|a| a > start) {
        return Activity::NotYetActive;
    }
    Activity::Active
}

/// What the rule does in an evaluation at `clock`: its own action, an
/// `audit` (an expired rule with `on_expire: convert_to_audit`), or
/// nothing.
#[must_use]
pub fn effective_action(rule: &Rule, clock: &RuleClock) -> Option<Action> {
    match activity(rule, clock) {
        Activity::Active => Some(rule.action.clone()),
        Activity::Expired if rule.on_expire == OnExpire::ConvertToAudit => Some(Action::Audit {}),
        Activity::Expired | Activity::Disabled | Activity::NotYetActive => None,
    }
}

/// Whether `rule` is an exception by its nature or by its metadata (see
/// the module documentation).
#[must_use]
pub fn is_exception(rule: &Rule) -> bool {
    if rule.metadata.exception || matches!(rule.action, Action::Ignore {}) {
        return true;
    }
    if !rule.action.kind().permits() {
        return false;
    }
    let weak = crate::analysis::identity::weakest_identity(&rule.match_);
    weak.is_weak() || crate::analysis::identity::has_path_identity(&rule.match_)
}

/// Whether a rule of this action needs a review date: allow and trust rules.
#[must_use]
pub const fn needs_review(kind: ActionKind) -> bool {
    kind.permits() || matches!(kind, ActionKind::TrustSource)
}

/// When the object is due for review: `review_by`, or for an allow or trust
/// rule without one, a year after `created_at`. `None` if neither is known.
#[must_use]
pub fn review_by(metadata: &Metadata, kind: Option<ActionKind>) -> Option<Date> {
    metadata.review_by.or_else(|| {
        kind.filter(|k| needs_review(*k))
            .and(metadata.created_at)
            .and_then(|c| c.plus_days(REVIEW_PERIOD_DAYS))
            .map(Timestamp::date)
    })
}

/// A reference to one rule in a document, for review queues and reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct RuleLocation {
    /// The rule set.
    pub rule_set_id: RuleSetId,
    /// The rule.
    pub rule_id: RuleId,
}

/// One rule due for review.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReviewItem {
    /// The rule.
    pub rule: RuleLocation,
    /// When it is due.
    pub review_by: Date,
    /// Its owner, if set.
    pub owner: Option<String>,
    /// Whether it is an exception.
    pub exception: bool,
}

/// The rules of the policy's referenced rule sets that are due for review
/// on or before `as_of`: their [`review_by`] date is at or before it. A
/// rule whose `review_by` cannot be determined is due at once. Sorted by
/// date, then rule set and rule ID, so the result is deterministic
/// evidence (ISM-1582).
#[must_use]
pub fn review_due(doc: &PolicyDocument, as_of: Date) -> Vec<ReviewItem> {
    let mut out: Vec<ReviewItem> = referenced(doc)
        .flat_map(|set| set.rules.iter().map(move |r| (set, r)))
        .filter(|(_, r)| r.enabled && needs_review(r.action.kind()))
        .filter_map(|(set, r)| {
            let due = review_by(&r.metadata, Some(r.action.kind())).unwrap_or(Date(i64::MIN));
            (due <= as_of).then(|| ReviewItem {
                rule: RuleLocation {
                    rule_set_id: set.id,
                    rule_id: r.id,
                },
                review_by: due,
                owner: r.metadata.owner.clone(),
                exception: is_exception(r),
            })
        })
        .collect();
    out.sort_by_key(|a| (a.review_by, a.rule));
    out
}

/// A deterministic summary of the review state, for evidence packs (#17).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ReviewSummary {
    /// Rules that need a review date.
    pub reviewable: usize,
    /// Of those, due on or before the date.
    pub due: usize,
    /// Of those, exceptions.
    pub exceptions_due: usize,
    /// Rules reviewed in the last 365 days.
    pub reviewed_last_year: usize,
    /// The earliest due date, if any.
    pub earliest_due: Option<Date>,
}

/// The review summary of a policy on `as_of`.
#[must_use]
pub fn review_summary(doc: &PolicyDocument, as_of: Date) -> ReviewSummary {
    let due = review_due(doc, as_of);
    let since = Date(as_of.0 - REVIEW_PERIOD_DAYS).start();
    let reviewable: Vec<&Rule> = referenced(doc)
        .flat_map(|s| &s.rules)
        .filter(|r| r.enabled && needs_review(r.action.kind()))
        .collect();
    ReviewSummary {
        reviewable: reviewable.len(),
        due: due.len(),
        exceptions_due: due.iter().filter(|d| d.exception).count(),
        reviewed_last_year: reviewable
            .iter()
            .filter(|r| r.metadata.last_reviewed_at.is_some_and(|t| t >= since))
            .count(),
        earliest_due: due.first().map(|d| d.review_by),
    }
}

/// A review action on one rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReviewAction {
    /// The rule is still needed as it is: the next review is a year on.
    Attest,
    /// The rule is renewed: as attest, and its expiry moves to
    /// `expires_at`.
    Renew {
        /// The new expiry.
        expires_at: Option<Timestamp>,
    },
    /// The rule is no longer needed: it is disabled.
    Retire,
}

/// Applies a review action to `rule`, by `reviewer` at `now`: sets
/// `last_reviewed_at` and `last_reviewed_by`, and `review_by` a year on.
pub fn review(rule: &mut Rule, action: &ReviewAction, reviewer: &str, now: Timestamp) {
    rule.metadata.last_reviewed_at = Some(now);
    rule.metadata.last_reviewed_by = Some(reviewer.to_owned());
    rule.metadata.updated_at = Some(now);
    rule.metadata.updated_by = Some(reviewer.to_owned());
    match action {
        ReviewAction::Attest => {}
        ReviewAction::Renew { expires_at } => rule.expires_at = *expires_at,
        ReviewAction::Retire => rule.enabled = false,
    }
    rule.metadata.review_by = now.plus_days(REVIEW_PERIOD_DAYS).map(Timestamp::date);
}

/// One expiry notice the server sends to a rule's owner (#16):
/// `rule.expiring`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExpiryNotice {
    /// The rule.
    pub rule: RuleLocation,
    /// Its owner, if set.
    pub owner: Option<String>,
    /// When it expires.
    pub expires_at: Timestamp,
    /// How many days before expiry this notice is: one of the policy's
    /// `expiry_notice_days`, `0` at expiry.
    pub days_before: u16,
    /// When the notice is due.
    pub due_at: Timestamp,
}

/// The expiry notices due in `(since, until]`, for every rule of the
/// policy's referenced rule sets with an `expires_at`. The server calls
/// this on a schedule with the previous run's `until` as `since`, so each
/// notice is sent once. Sorted by due time, then rule.
#[must_use]
pub fn expiry_notices(
    doc: &PolicyDocument,
    since: Timestamp,
    until: Timestamp,
) -> Vec<ExpiryNotice> {
    let days = &doc.policy.governance.expiry_notice_days;
    let mut out = Vec::new();
    for set in referenced(doc) {
        for r in set.rules.iter().filter(|r| r.enabled) {
            let Some(expires_at) = r.expires_at else {
                continue;
            };
            for d in days {
                let Some(due_at) = expires_at.plus_days(-i64::from(*d)) else {
                    continue;
                };
                if since < due_at && due_at <= until {
                    out.push(ExpiryNotice {
                        rule: RuleLocation {
                            rule_set_id: set.id,
                            rule_id: r.id,
                        },
                        owner: r.metadata.owner.clone(),
                        expires_at,
                        days_before: *d,
                        due_at,
                    });
                }
            }
        }
    }
    out.sort_by_key(|a| (a.due_at, a.rule, a.days_before));
    out.dedup_by(|a, b| a.rule == b.rule && a.due_at == b.due_at);
    out
}

/// The expired rules whose `on_expire: delete_after_days` has passed at
/// `now`: the server deletes them in a change set. Sorted.
#[must_use]
pub fn retire_due(doc: &PolicyDocument, now: Timestamp) -> Vec<RuleLocation> {
    let mut out: Vec<RuleLocation> = doc
        .rule_sets
        .iter()
        .flat_map(|set| set.rules.iter().map(move |r| (set, r)))
        .filter_map(|(set, r)| match (r.on_expire, r.expires_at) {
            (OnExpire::DeleteAfterDays(days), Some(e))
                if e.plus_days(i64::from(days)).is_some_and(|t| t <= now) =>
            {
                Some(RuleLocation {
                    rule_set_id: set.id,
                    rule_id: r.id,
                })
            }
            _ => None,
        })
        .collect();
    out.sort();
    out
}

/// A bulk operation on several rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BulkOp {
    /// Enable the rules.
    Enable,
    /// Disable the rules.
    Disable,
    /// Move each rule's expiry to this instant.
    Extend(Timestamp),
    /// Disable the rules, and mark them retired with a comment.
    Retire,
}

/// One change of a [`ChangeSet`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleChange {
    /// The rule.
    pub rule: RuleLocation,
    /// `enabled` before and after.
    pub enabled: (bool, bool),
    /// `expires_at` before and after.
    pub expires_at: (Option<Timestamp>, Option<Timestamp>),
}

/// A bulk operation recorded as one change, with its reason, for the
/// immutable change history (#10).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChangeSet {
    /// Who made it.
    pub actor: String,
    /// When.
    pub at: Timestamp,
    /// Why.
    pub reason: String,
    /// Each rule changed, sorted.
    pub changes: Vec<RuleChange>,
}

/// Why a bulk operation was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BulkError {
    /// No reason was given.
    ReasonRequired,
    /// A rule is not in the document.
    UnknownRule(RuleLocation),
    /// A read-only rule set cannot be edited.
    ReadOnly(RuleLocation),
}

impl core::fmt::Display for BulkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ReasonRequired => f.write_str("a bulk change needs a reason"),
            Self::UnknownRule(r) => {
                write!(f, "rule {} is not in rule set {}", r.rule_id, r.rule_set_id)
            }
            Self::ReadOnly(r) => write!(f, "rule set {} is read-only", r.rule_set_id),
        }
    }
}

impl std::error::Error for BulkError {}

/// Applies `op` to every rule in `rules`, as one change set with `reason`.
/// Nothing changes unless every rule can be changed.
///
/// # Errors
///
/// Returns [`BulkError`] if there is no reason, a rule is missing, or a
/// rule set is read-only.
pub fn bulk(
    doc: &mut PolicyDocument,
    rules: &[RuleLocation],
    op: &BulkOp,
    actor: &str,
    reason: &str,
    at: Timestamp,
) -> Result<ChangeSet, BulkError> {
    if reason.trim().is_empty() {
        return Err(BulkError::ReasonRequired);
    }
    for loc in rules {
        let set = doc
            .rule_sets
            .iter()
            .find(|s| s.id == loc.rule_set_id)
            .filter(|s| s.rules.iter().any(|r| r.id == loc.rule_id))
            .ok_or(BulkError::UnknownRule(*loc))?;
        if set.read_only {
            return Err(BulkError::ReadOnly(*loc));
        }
    }
    let mut changes = Vec::new();
    let mut wanted: Vec<RuleLocation> = rules.to_vec();
    wanted.sort();
    wanted.dedup();
    for loc in wanted {
        let Some(rule) = doc
            .rule_sets
            .iter_mut()
            .filter(|s| s.id == loc.rule_set_id)
            .flat_map(|s| s.rules.iter_mut())
            .find(|r| r.id == loc.rule_id)
        else {
            continue;
        };
        let before = (rule.enabled, rule.expires_at);
        match op {
            BulkOp::Enable => rule.enabled = true,
            BulkOp::Disable => rule.enabled = false,
            BulkOp::Extend(t) => rule.expires_at = Some(*t),
            BulkOp::Retire => {
                rule.enabled = false;
                rule.metadata.comment = Some(format!("retired: {}", reason.trim()));
            }
        }
        rule.metadata.updated_by = Some(actor.to_owned());
        rule.metadata.updated_at = Some(at);
        changes.push(RuleChange {
            rule: loc,
            enabled: (before.0, rule.enabled),
            expires_at: (before.1, rule.expires_at),
        });
    }
    Ok(ChangeSet {
        actor: actor.to_owned(),
        at,
        reason: reason.trim().to_owned(),
        changes,
    })
}

/// The rules that would have matched `subject` but are inactive at
/// `clock`, with why, sorted by rule ID: what the decision trace (#41)
/// reports as "would have matched disabled rule R" or "expired rule R".
/// Not for the hot path: it compiles each inactive rule's tree.
#[must_use]
pub fn inactive_matches(
    validated: &crate::validate::ValidatedPolicy,
    subject: &crate::evaluate::Subject<'_>,
    clock: &RuleClock,
) -> Vec<(RuleRef, Activity)> {
    let doc = validated.document();
    let mut out: Vec<(RuleRef, Activity)> = referenced(doc)
        .flat_map(|set| set.rules.iter().map(move |r| (set, r)))
        .filter_map(|(set, rule)| {
            let why = activity(rule, clock);
            if why.is_active() {
                return None;
            }
            if !rule.object_types.is_empty() && !rule.object_types.contains(&subject.object_type) {
                return None;
            }
            let tree = crate::condition::CompiledMatch::compile(&rule.match_).ok()?;
            let ctx = crate::ops::EvalContext {
                action: rule.action.kind(),
                variables: subject.variables,
                context: subject.context,
            };
            tree.eval(subject.facts, &ctx)
                .matches()
                .then(|| (RuleRef::new(&doc.policy, set, rule), why))
        })
        .collect();
    out.sort_by_key(|(r, _)| r.rule_id);
    out
}

impl PolicyDocument {
    /// The document without its governance metadata: what decides (#40,
    /// #43). Metadata never changes a decision, so a bundle's
    /// decision-relevant hash is taken over this form, and editing a
    /// justification or a review date does not make agents re-verify
    /// their decision caches. The full content hash still covers it.
    #[must_use]
    pub fn decision_relevant(&self) -> Self {
        let mut doc = self.clone();
        doc.policy.metadata = Metadata::default();
        doc.policy.governance = crate::model::GovernanceSettings::default();
        for set in &mut doc.rule_sets {
            set.metadata = Metadata::default();
            for rule in &mut set.rules {
                rule.metadata = Metadata::default();
            }
        }
        doc
    }
}

/// The rule sets the policy references, in its order.
pub(crate) fn referenced(doc: &PolicyDocument) -> impl Iterator<Item = &RuleSet> {
    doc.policy
        .rule_sets
        .iter()
        .filter_map(|id| doc.rule_sets.iter().find(|s| s.id == *id))
}

/// The reference a decision uses for `rule`.
#[must_use]
pub fn rule_ref(policy: &Policy, set: &RuleSet, rule: &Rule) -> RuleRef {
    RuleRef::new(policy, set, rule)
}

#[cfg(test)]
mod tests;
