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
//! Activity is checked against a [`RuleClock`]: the agent's time `now`,
//! its **floor** (the lower bound on real time that the agent keeps in
//! protected storage and never lowers), and whether the agent is
//! **anchored** (ADR 0012, ADR 0018). While the agent is anchored, `now`
//! is anchored time and the floor is raised to it, so the two agree. An
//! **offline-started** agent (after a restart, before its next check-in)
//! has only the wall clock for `now`, which anyone who can change the
//! clock controls.
//!
//! While the agent is offline-started, a time-bounded rule that lets an
//! object run, trusts it or excludes it ([`ActionKind::needs_identity`]) is
//! inactive, whatever the readings say: grants from the policy bundle do
//! not start or continue until the next check-in (ADR 0018, rule 2). It is
//! reported as `expired` once the floor has passed its expiry, and as
//! `not_yet_active` otherwise. This is the same result as with no clock at
//! all ([`activity_at`]). Every other rule, and every rule while anchored,
//! is judged from the two readings, each in the closed direction:
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
//! `approved_at`, `expires_at` at most 365 days after it, `justification`,
//! `approved_by` and `risk_rating` ([`crate::validate`], `exception_*`
//! codes). The year counts from `approved_at` only ([`exception_start`]):
//! only a renewal in a review ([`ReviewAction::Renew`]) moves it, so an
//! attestation or a bulk extension never stretches an exception past a
//! year from its approval.

pub mod counters;

use serde::Serialize;

use crate::decision::RuleRef;
use crate::model::lifecycle::limits::REVIEW_PERIOD_DAYS;
use crate::model::{
    Action, ActionKind, Date, Metadata, OnExpire, Policy, PolicyDocument, Rule, RuleId, RuleSet,
    RuleSetId, Timestamp,
};

pub use counters::{Counters, HitReport, RuleHits};

/// The agent's view of time for rule activity (ADR 0012, ADR 0018).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RuleClock {
    /// The current time: anchored time while the agent is anchored, or
    /// the wall clock while it is offline-started. The server and tests
    /// pass real time.
    pub now: Timestamp,
    /// The lower bound on real time the agent keeps in protected storage,
    /// which never goes backwards. Pass `now` where there is none (the
    /// server, the policy assistant).
    pub floor: Timestamp,
    /// Whether `now` is trusted time: the agent holds anchored time, or
    /// the caller is the server. `false` while the agent is
    /// offline-started; time-bounded permissive rules are then inactive
    /// (see the module documentation).
    pub anchored: bool,
}

impl RuleClock {
    /// An anchored clock whose floor is `now`: for the server, the policy
    /// assistant and tests.
    #[must_use]
    pub const fn at(now: Timestamp) -> Self {
        Self {
            now,
            floor: now,
            anchored: true,
        }
    }

    /// The clock of an offline-started agent: the wall clock `now` and
    /// the stored floor.
    #[must_use]
    pub const fn offline_started(now: Timestamp, floor: Timestamp) -> Self {
        Self {
            now,
            floor,
            anchored: false,
        }
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
    let permissive = rule.action.kind().needs_identity();
    let timed = rule.activates_at.is_some() || rule.expires_at.is_some();
    // Offline-started: no bundle grant starts or continues (ADR 0018).
    if permissive && timed && !clock.anchored {
        return if rule.expires_at.is_some_and(|e| e <= clock.floor) {
            Activity::Expired
        } else {
            Activity::NotYetActive
        };
    }
    // A permissive rule needs both readings inside its window; any other
    // rule needs only one.
    let (start, end) = if permissive {
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

/// Whether `rule` is active at `clock`, or with no clock at all: then a
/// time-bounded rule that lets an object run, trusts it or excludes it is
/// `not_yet_active`, and any other rule is active (the closed direction).
/// The evaluator, the decision trace and the effective view all judge
/// activity with this.
#[must_use]
pub fn activity_at(rule: &Rule, clock: Option<&RuleClock>) -> Activity {
    if !rule.enabled {
        return Activity::Disabled;
    }
    if rule.activates_at.is_none() && rule.expires_at.is_none() {
        return Activity::Active;
    }
    match clock {
        Some(clock) => activity(rule, clock),
        None if rule.action.kind().needs_identity() => Activity::NotYetActive,
        None => Activity::Active,
    }
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

/// When an exception's year starts: its approval, `approved_at`. Neither
/// `created_at` nor `last_reviewed_at` counts, so a creation date written
/// in the future or an attestation cannot stretch it. Only a renewal in a
/// review ([`ReviewAction::Renew`]) re-approves an exception and so moves
/// its start.
#[must_use]
pub const fn exception_start(m: &Metadata) -> Option<Timestamp> {
    m.approved_at
}

/// The latest expiry an exception may have: 365 days after its approval,
/// counted from no later than `now` when a time is known, so an approval
/// dated in the future cannot stretch it. `None` without `approved_at`.
#[must_use]
pub fn exception_limit(m: &Metadata, now: Option<Timestamp>) -> Option<Timestamp> {
    let start = exception_start(m)?;
    let start = now.map_or(start, |n| start.min(n));
    start.plus_days(crate::model::lifecycle::limits::MAX_EXCEPTION_DAYS)
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
    /// When it is due, or `null` when no date can be determined (no
    /// `review_by` and no `created_at`): such a rule is due at once.
    pub review_by: Option<Date>,
    /// Its owner, if set.
    pub owner: Option<String>,
    /// Whether it is an exception.
    pub exception: bool,
}

/// The rules a review campaign covers: enabled allow and trust rules of
/// the policy's referenced rule sets, other than the managed
/// `system_baseline` the engine builds ([`managed_baseline`]). A
/// read-only (curated) rule set is reviewed like any other.
fn reviewable(doc: &PolicyDocument) -> impl Iterator<Item = (&RuleSet, &Rule)> {
    let exempt = managed_baseline(doc);
    referenced(doc)
        .filter(move |set| Some(set.id) != exempt)
        .flat_map(|set| set.rules.iter().map(move |r| (set, r)))
        .filter(|(_, r)| r.enabled && needs_review(r.action.kind()))
}

/// The rules due for review on or before `as_of`: their [`review_by`] date
/// is at or before it, or cannot be determined. Sorted, undated first, then
/// by date, rule set and rule ID, so the result is deterministic evidence
/// (ISM-1582).
#[must_use]
pub fn review_due(doc: &PolicyDocument, as_of: Date) -> Vec<ReviewItem> {
    let mut out: Vec<ReviewItem> = reviewable(doc)
        .filter_map(|(set, r)| {
            let due = review_by(&r.metadata, Some(r.action.kind()));
            due.is_none_or(|d| d <= as_of).then(|| ReviewItem {
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
    /// Of those, with no date that can be determined.
    pub undated: usize,
    /// The earliest due date among the dated ones, if any.
    pub earliest_due: Option<Date>,
}

/// The review summary of a policy on `as_of`.
#[must_use]
pub fn review_summary(doc: &PolicyDocument, as_of: Date) -> ReviewSummary {
    let due = review_due(doc, as_of);
    let since = as_of.start().plus_days(-REVIEW_PERIOD_DAYS);
    let rules: Vec<&Rule> = reviewable(doc).map(|(_, r)| r).collect();
    ReviewSummary {
        reviewable: rules.len(),
        due: due.len(),
        exceptions_due: due.iter().filter(|d| d.exception).count(),
        reviewed_last_year: rules
            .iter()
            .filter(|r| {
                r.metadata
                    .last_reviewed_at
                    .is_some_and(|t| since.is_none_or(|s| t >= s))
            })
            .count(),
        undated: due.iter().filter(|d| d.review_by.is_none()).count(),
        earliest_due: due.iter().find_map(|d| d.review_by),
    }
}

/// A review action on one rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReviewAction {
    /// The rule is still needed as it is: the next review is a year on.
    /// An exception's approval, and so its 365-day limit, is unchanged.
    Attest,
    /// The rule is renewed: as attest, and its expiry moves to
    /// `expires_at`. An exception is re-approved by the reviewer at the
    /// review ([`exception_start`]), so `expires_at` must be at most 365
    /// days after it.
    Renew {
        /// The new expiry.
        expires_at: Timestamp,
    },
    /// The rule is no longer needed: it is disabled.
    Retire,
}

/// Why a review or bulk change was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChangeError {
    /// The actor or reviewer is empty, untrimmed or too long.
    InvalidActor,
    /// The new expiry is not after `now`, or not after `activates_at`.
    InvalidExpiry,
    /// The time is past the representable range.
    TimeOverflow,
    /// Renewing an exception for more than 365 days.
    ExceptionTooLong,
}

impl core::fmt::Display for ChangeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidActor => "the actor must be 1 to 128 trimmed characters",
            Self::InvalidExpiry => "the new expiry must be in the future and after `activates_at`",
            Self::TimeOverflow => "the time is out of range",
            Self::ExceptionTooLong => {
                "an exception is renewed for at most 365 days from the review"
            }
        })
    }
}

impl std::error::Error for ChangeError {}

/// Whether `actor` is a valid metadata name: 1 to 128 trimmed characters
/// with no control characters.
fn valid_actor(actor: &str) -> bool {
    !actor.is_empty()
        && actor.trim() == actor
        && actor.chars().count() <= crate::model::limits::MAX_NAME_CHARS
        && !actor.chars().any(char::is_control)
}

/// Applies a review action to `rule`, by `reviewer` at `now`: sets
/// `last_reviewed_at` and `last_reviewed_by`, and `review_by` a year on.
/// The rule stays valid: renewing an exception re-approves it, so its
/// expiry is checked from the review. Attesting never moves
/// `approved_at`.
///
/// # Errors
///
/// Returns [`ChangeError`] for an invalid reviewer or expiry; the rule is
/// then unchanged.
pub fn review(
    rule: &mut Rule,
    action: &ReviewAction,
    reviewer: &str,
    now: Timestamp,
) -> Result<(), ChangeError> {
    if !valid_actor(reviewer) {
        return Err(ChangeError::InvalidActor);
    }
    let next = now
        .plus_days(REVIEW_PERIOD_DAYS)
        .map(Timestamp::date)
        .ok_or(ChangeError::TimeOverflow)?;
    if let ReviewAction::Renew { expires_at } = action {
        if *expires_at <= now || rule.activates_at.is_some_and(|a| *expires_at <= a) {
            return Err(ChangeError::InvalidExpiry);
        }
        if is_exception(rule)
            && now
                .plus_days(crate::model::lifecycle::limits::MAX_EXCEPTION_DAYS)
                .is_none_or(|l| *expires_at > l)
        {
            return Err(ChangeError::ExceptionTooLong);
        }
    }
    rule.metadata.last_reviewed_at = Some(now);
    rule.metadata.last_reviewed_by = Some(reviewer.to_owned());
    rule.metadata.updated_at = Some(now);
    rule.metadata.updated_by = Some(reviewer.to_owned());
    match action {
        ReviewAction::Attest => {}
        ReviewAction::Renew { expires_at } => {
            rule.expires_at = Some(*expires_at);
            if is_exception(rule) {
                rule.metadata.approved_by = Some(reviewer.to_owned());
                rule.metadata.approved_at = Some(now);
            }
        }
        ReviewAction::Retire => rule.enabled = false,
    }
    rule.metadata.review_by = Some(next);
    Ok(())
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
    /// `metadata.comment` before and after.
    pub comment: (Option<String>, Option<String>),
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
    /// The actor is not a valid name, or an expiry is not after the time
    /// of the change.
    Invalid(ChangeError),
    /// Extending would put an exception's expiry more than 365 days after
    /// its approval: renew it in a review instead, which re-approves it.
    ExceptionTooLong(RuleLocation),
    /// Enabling the rule would leave the document invalid in governance
    /// mode: it lacks the metadata these codes name.
    Governance(RuleLocation, Vec<crate::validate::ErrorCode>),
}

impl core::fmt::Display for BulkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ReasonRequired => f.write_str("a bulk change needs a reason"),
            Self::UnknownRule(r) => {
                write!(f, "rule {} is not in rule set {}", r.rule_id, r.rule_set_id)
            }
            Self::ReadOnly(r) => write!(f, "rule set {} is read-only", r.rule_set_id),
            Self::Invalid(e) => e.fmt(f),
            Self::ExceptionTooLong(r) => write!(
                f,
                "rule {} is an exception, and the new expiry is more than 365 days after its approval; renew it in a review",
                r.rule_id
            ),
            Self::Governance(r, codes) => {
                let names: Vec<&str> = codes.iter().map(|c| c.as_str()).collect();
                write!(
                    f,
                    "rule {} cannot be enabled in governance mode until its metadata is complete: {}",
                    r.rule_id,
                    names.join(", ")
                )
            }
        }
    }
}

impl std::error::Error for BulkError {}

/// Applies `op` to every rule in `rules`, as one change set with `reason`.
/// Nothing changes unless every rule can be changed.
///
/// # Errors
///
/// Returns [`BulkError`] if there is no reason, a rule is missing, a rule
/// set is read-only, an exception would be extended past a year from its
/// approval, or a rule to enable lacks the metadata governance mode needs.
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
    if !valid_actor(actor) {
        return Err(BulkError::Invalid(ChangeError::InvalidActor));
    }
    for loc in rules {
        let set = doc
            .rule_sets
            .iter()
            .find(|s| s.id == loc.rule_set_id)
            .ok_or(BulkError::UnknownRule(*loc))?;
        let rule = set
            .rules
            .iter()
            .find(|r| r.id == loc.rule_id)
            .ok_or(BulkError::UnknownRule(*loc))?;
        if set.read_only {
            return Err(BulkError::ReadOnly(*loc));
        }
        if let BulkOp::Extend(t) = op {
            if *t <= at || rule.activates_at.is_some_and(|a| *t <= a) {
                return Err(BulkError::Invalid(ChangeError::InvalidExpiry));
            }
            if is_exception(rule)
                && exception_limit(&rule.metadata, Some(at)).is_none_or(|l| *t > l)
            {
                return Err(BulkError::ExceptionTooLong(*loc));
            }
        }
        if *op == BulkOp::Enable && !rule.enabled {
            let mut enabled = rule.clone();
            enabled.enabled = true;
            let codes: Vec<_> = crate::validate::governance_problems(doc, set, &enabled)
                .into_iter()
                .map(|(code, _, _)| code)
                .collect();
            if !codes.is_empty() {
                return Err(BulkError::Governance(*loc, codes));
            }
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
        let before = (rule.enabled, rule.expires_at, rule.metadata.comment.clone());
        match op {
            BulkOp::Enable => rule.enabled = true,
            BulkOp::Disable => rule.enabled = false,
            BulkOp::Extend(t) => rule.expires_at = Some(*t),
            BulkOp::Retire => {
                rule.enabled = false;
                // Kept within the text limit; the full reason is in the
                // change set.
                let note = format!("retired: {}", reason.trim());
                let text = match &rule.metadata.comment {
                    Some(c) => format!("{c}\n{note}"),
                    None => note,
                };
                rule.metadata.comment = Some(
                    text.chars()
                        .take(crate::model::limits::MAX_TEXT_CHARS)
                        .collect(),
                );
            }
        }
        rule.metadata.updated_by = Some(actor.to_owned());
        rule.metadata.updated_at = Some(at);
        changes.push(RuleChange {
            rule: loc,
            enabled: (before.0, rule.enabled),
            expires_at: (before.1, rule.expires_at),
            comment: (before.2, rule.metadata.comment.clone()),
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
            // `defer` is never evaluated, active or not.
            if matches!(rule.action, Action::Defer {})
                || (!rule.object_types.is_empty()
                    && !rule.object_types.contains(&subject.object_type))
            {
                return None;
            }
            let tree = crate::condition::CompiledMatch::compile(&rule.match_).ok()?;
            let ctx = crate::ops::EvalContext {
                action: rule.action.kind(),
                variables: subject.variables,
                context: subject.context,
            };
            // As the evaluator applies it: a deny's unknown handling counts.
            let (unknown_as, unparseable) = match &rule.action {
                Action::Deny(o) => (
                    o.unknown_as,
                    match o.on_unparseable {
                        crate::model::UnknownAs::Match => {
                            crate::condition::Unparseable::FavourMatch
                        }
                        crate::model::UnknownAs::NoMatch => crate::condition::Unparseable::Unknown,
                    },
                ),
                _ => (
                    crate::model::UnknownAs::NoMatch,
                    crate::condition::Unparseable::Unknown,
                ),
            };
            let matched = match tree.eval_with(subject.facts, &ctx, unparseable).result {
                crate::ops::Tri::Match => true,
                crate::ops::Tri::Unknown => unknown_as == crate::model::UnknownAs::Match,
                crate::ops::Tri::NoMatch => false,
            };
            matched.then(|| (RuleRef::new(&doc.policy, set, rule), why))
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

/// The managed `system_baseline` rule set, if the document holds the one
/// the engine builds ([`crate::unknown::baseline::is_generated_baseline`]).
/// It is the only rule set exempt from governance and review campaigns: a
/// document that merely marks a rule set `read_only`, or gives it the
/// baseline's ID, gets no exemption.
pub(crate) fn managed_baseline(doc: &PolicyDocument) -> Option<RuleSetId> {
    doc.rule_sets
        .iter()
        .find(|s| crate::unknown::baseline::is_generated_baseline(s, &doc.policy))
        .map(|s| s.id)
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
