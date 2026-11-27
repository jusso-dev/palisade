//! The policy assistant: static analysis of a policy (#40).
//!
//! [`analyse`] runs on every save, on bundle compile ([`publish_gate`]) and
//! on demand (the CLI's `pal policy lint`, #15). Each [`Finding`] has a
//! stable [`FindingCode`], a severity, the rules it is about, a message and
//! an optional suggested fix. Findings are sorted, so the output is a
//! deterministic function of the policy, the facts and the time.
//!
//! A policy can raise a finding's severity (`policy.governance.severity`),
//! never lower it below the code's default: validation rejects that, and
//! the assistant reports the higher of the two. `error` findings block
//! publishing unless a tenant administrator overrides them with a reason
//! ([`publish_gate`]).
//!
//! # Conflicts
//!
//! `shadowed`, `contradiction` and `ineffective_vs_mandatory` need a proof
//! that one rule matches whenever another does ([`subsume::covers`]). The
//! proof is conservative: a finding is only made when it is certain, so a
//! rule reported as shadowed or ineffective truly never decides (a property
//! test checks this against the evaluator). Rules are compared only when
//! they share an identity value (an exact hash, publisher or path), which
//! keeps the analysis near linear on large policies.
//!
//! - `ineffective_vs_mandatory`: an allow that a mandatory deny always
//!   blocks first (stage 1).
//! - `shadowed`: a rule that another rule of the same verdict always
//!   outranks, under the policy's model, so it never decides. Only proven
//!   for `deny_wins` among denies and for `first_match`, where the outcome
//!   order is fixed. Other cases are left to the decision trace (#41).
//! - `contradiction`: an allow and a deny where one covers the other, so
//!   for some objects both match, and the precedence model alone decides.
//!   Under `deny_wins`, an allow covered by a deny never decides, which is
//!   reported as `shadowed` instead.

pub mod identity;
pub mod subsume;

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::lifecycle::{Activity, RuleClock, activity, is_exception, needs_review, review_by};
use crate::model::lifecycle::limits::MAX_EXCEPTION_DAYS;
use crate::model::{
    Action, ActionKind, Criterion, Date, Field, FieldClass, FindingSeverity, Match, Operator,
    PolicyDocument, PrecedenceModel, Rule, RuleId, RuleSet, RuleSetId, Timestamp,
};
use crate::ops::REGEX_SIZE_LIMIT;
use crate::precedence::Verdict;
use identity::{Guaranteed, weakest_identity};
use subsume::covers;

/// The stable code of a finding. The `snake_case` name is part of the API.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FindingCode {
    /// An allow on a weak identity: a file name, metadata, an extension,
    /// SHA-1 or MD5 only, or a path whose ACL safety is not proven (#31).
    WeakIdentity,
    /// A path allow on a location the writable-path scanner flagged.
    UserWritablePathAllow,
    /// A publisher-only allow for a restricted publisher (#31).
    RestrictedPublisherBroad,
    /// A very broad wildcard or regular expression.
    BroadWildcard,
    /// A rule that never decides, because another always outranks it.
    Shadowed,
    /// An allow and a deny that both match some objects.
    Contradiction,
    /// An allow that a mandatory deny always blocks first.
    IneffectiveVsMandatory,
    /// Two rules with the same normalised match, action and scope.
    DuplicateRule,
    /// A principal in both the positive and the negative test of a rule,
    /// or repeated in one test.
    DuplicatePrincipal,
    /// An expired rule still in the policy.
    ExpiredRulePresent,
    /// A rule that expires soon.
    ExpiringSoon,
    /// A rule whose review date has passed.
    ReviewOverdue,
    /// A rule with no hits for `stale_after_days` while devices in scope
    /// were online.
    StaleRule,
    /// A publisher or thumbprint rule whose certificate is revoked or
    /// expired.
    RevokedOrExpiredSigner,
    /// An allow covering a version range that a mandatory or curated
    /// blocklist marks vulnerable.
    VulnerableVersionAllowed,
    /// A rule that needs a justification has none (governance mode).
    MissingJustification,
    /// An exception without an expiry, approver or risk rating, or with an
    /// expiry more than a year away (governance mode).
    ExceptionWithoutExpiry,
    /// More inline hash values than the engine keeps in a list (#42).
    TooManyHashRules,
    /// A regular expression near the size limit.
    RegexCost,
    /// `approved_at`, `created_at` or `last_reviewed_at` is in the future.
    FutureDatedMetadata,
}

impl FindingCode {
    /// Every code.
    pub const ALL: [Self; 20] = [
        Self::WeakIdentity,
        Self::UserWritablePathAllow,
        Self::RestrictedPublisherBroad,
        Self::BroadWildcard,
        Self::Shadowed,
        Self::Contradiction,
        Self::IneffectiveVsMandatory,
        Self::DuplicateRule,
        Self::DuplicatePrincipal,
        Self::ExpiredRulePresent,
        Self::ExpiringSoon,
        Self::ReviewOverdue,
        Self::StaleRule,
        Self::RevokedOrExpiredSigner,
        Self::VulnerableVersionAllowed,
        Self::MissingJustification,
        Self::ExceptionWithoutExpiry,
        Self::TooManyHashRules,
        Self::RegexCost,
        Self::FutureDatedMetadata,
    ];

    /// The stable `snake_case` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WeakIdentity => "weak_identity",
            Self::UserWritablePathAllow => "user_writable_path_allow",
            Self::RestrictedPublisherBroad => "restricted_publisher_broad",
            Self::BroadWildcard => "broad_wildcard",
            Self::Shadowed => "shadowed",
            Self::Contradiction => "contradiction",
            Self::IneffectiveVsMandatory => "ineffective_vs_mandatory",
            Self::DuplicateRule => "duplicate_rule",
            Self::DuplicatePrincipal => "duplicate_principal",
            Self::ExpiredRulePresent => "expired_rule_present",
            Self::ExpiringSoon => "expiring_soon",
            Self::ReviewOverdue => "review_overdue",
            Self::StaleRule => "stale_rule",
            Self::RevokedOrExpiredSigner => "revoked_or_expired_signer",
            Self::VulnerableVersionAllowed => "vulnerable_version_allowed",
            Self::MissingJustification => "missing_justification",
            Self::ExceptionWithoutExpiry => "exception_without_expiry",
            Self::TooManyHashRules => "too_many_hash_rules",
            Self::RegexCost => "regex_cost",
            Self::FutureDatedMetadata => "future_dated_metadata",
        }
    }

    /// The default severity. A policy may raise it, but not lower it.
    #[must_use]
    pub const fn default_severity(self) -> FindingSeverity {
        match self {
            Self::IneffectiveVsMandatory
            | Self::RestrictedPublisherBroad
            | Self::RevokedOrExpiredSigner
            | Self::VulnerableVersionAllowed
            | Self::MissingJustification
            | Self::ExceptionWithoutExpiry => FindingSeverity::Error,
            Self::ExpiringSoon | Self::TooManyHashRules => FindingSeverity::Info,
            _ => FindingSeverity::Warning,
        }
    }

    /// The code with this name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == name)
    }
}

impl core::fmt::Display for FindingCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A rule a finding is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct RuleRef {
    /// The rule set.
    pub rule_set_id: RuleSetId,
    /// The rule.
    pub rule_id: RuleId,
}

/// A suggested change.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Fix {
    /// Remove the first rule.
    RemoveRule,
    /// Disable the first rule.
    DisableRule,
    /// Convert the first rule to `audit` (never automatic, #40).
    ConvertToAudit,
    /// Add the missing fields.
    AddMetadata {
        /// The fields, by name.
        fields: Vec<&'static str>,
    },
    /// Narrow the rule's identity, as described.
    Narrow {
        /// What to add.
        hint: &'static str,
    },
}

/// One finding of the policy assistant.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct Finding {
    /// The stable code.
    pub code: FindingCode,
    /// How serious it is, after the tenant's settings.
    pub severity: FindingSeverity,
    /// The rules it is about, the subject first.
    pub rule_refs: Vec<RuleRef>,
    /// An explanation.
    pub message: String,
    /// A suggested fix, if there is one.
    pub fix: Option<Fix>,
}

/// One rule's usage, for `stale_rule` (#40): from the server's aggregated
/// hit counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Usage {
    /// The rule's last match on any device, if any.
    pub last_matched_at: Option<Timestamp>,
    /// Whether any device in the rule's scope was online since the start of
    /// the stale window.
    pub devices_online: bool,
}

/// A signer certificate's state, for `revoked_or_expired_signer` (#3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CertificateState {
    /// The certificate is revoked.
    Revoked,
    /// The certificate has expired.
    Expired,
}

/// What the assistant knows beyond the policy. Every field is optional:
/// a check whose facts are missing is skipped.
#[derive(Clone, Debug, Default)]
pub struct Facts {
    /// Directories the writable-path scanner flagged (#5, #17).
    pub writable_dirs: Vec<String>,
    /// Publishers whose broad trust would allow living-off-the-land
    /// binaries, such as the OS publishers (#31): a publisher-only allow
    /// naming one is an error.
    pub restricted_publishers: Vec<String>,
    /// Revoked or expired signers, by publisher name or SHA-256
    /// thumbprint (#3).
    pub certificates: BTreeMap<String, CertificateState>,
    /// Usage per rule, for `stale_rule`.
    pub usage: BTreeMap<RuleId, Usage>,
    /// A sample of paths, for wildcards and regular expressions that match
    /// a large share of them (`broad_wildcard`).
    pub path_corpus: Vec<String>,
}

/// Settings of the analysis that are not tenant settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// A pattern matching this share of the path corpus, in percent, is
    /// broad.
    pub broad_corpus_percent: u8,
    /// More inline hash values than this in one rule set is reported.
    pub max_inline_hashes: usize,
    /// The most rule pairs the conflict checks compare, so a hostile
    /// policy cannot make an interactive save slow. Pairs past the limit
    /// are not checked, which can only miss findings.
    pub max_pair_checks: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            broad_corpus_percent: 20,
            max_inline_hashes: 50_000,
            max_pair_checks: 2_000_000,
        }
    }
}

/// One rule, with where it is.
#[derive(Clone, Copy)]
struct Entry<'d> {
    set: &'d RuleSet,
    rule: &'d Rule,
}

impl Entry<'_> {
    fn r(&self) -> RuleRef {
        RuleRef {
            rule_set_id: self.set.id,
            rule_id: self.rule.id,
        }
    }

    fn verdict(&self) -> Option<Verdict> {
        Verdict::of(&self.rule.action)
    }

    /// The scopes on the way to the rule (#38): its rule set's assignment
    /// scopes, then its own. The policy's scope covers every rule alike.
    fn scopes<'a>(&'a self, doc: &'a PolicyDocument) -> Vec<&'a crate::scope::Scope> {
        doc.policy
            .rule_set_scopes
            .iter()
            .filter(|a| a.rule_set == self.set.id)
            .flat_map(|a| &a.scopes)
            .chain(self.rule.scope.as_deref())
            .collect()
    }

    fn applies_to_all_types_of(&self, other: &Self) -> bool {
        self.rule.object_types.is_empty()
            || (!other.rule.object_types.is_empty()
                && other
                    .rule
                    .object_types
                    .iter()
                    .all(|t| self.rule.object_types.contains(t)))
    }
}

/// Runs every check on `doc` at `now`.
#[must_use]
pub fn analyse(doc: &PolicyDocument, facts: &Facts, now: Timestamp) -> Vec<Finding> {
    analyse_with(doc, facts, now, &Options::default())
}

/// [`analyse`], with options.
#[must_use]
pub fn analyse_with(
    doc: &PolicyDocument,
    facts: &Facts,
    now: Timestamp,
    options: &Options,
) -> Vec<Finding> {
    let mut a = Analyser {
        doc,
        facts,
        now,
        exempt: crate::lifecycle::managed_baseline(doc),
        clock: RuleClock::at(now),
        options,
        out: Vec::new(),
    };
    let entries: Vec<Entry<'_>> = crate::lifecycle::referenced(doc)
        .flat_map(|set| set.rules.iter().map(move |rule| (set, rule)))
        .map(|(set, rule)| Entry { set, rule })
        .collect();
    for e in &entries {
        a.rule_checks(e);
    }
    let active: Vec<Entry<'_>> = entries
        .iter()
        .copied()
        .filter(|e| activity(e.rule, &a.clock) == Activity::Active)
        .collect();
    a.duplicates(&active);
    a.conflicts(&active);
    a.hash_counts();
    a.finish()
}

struct Analyser<'a> {
    doc: &'a PolicyDocument,
    facts: &'a Facts,
    now: Timestamp,
    /// The managed `system_baseline`, if the document holds the one the
    /// engine built.
    exempt: Option<RuleSetId>,
    clock: RuleClock,
    options: &'a Options,
    out: Vec<Finding>,
}

impl Analyser<'_> {
    fn push(&mut self, code: FindingCode, refs: Vec<RuleRef>, message: String, fix: Option<Fix>) {
        let severity = self
            .doc
            .policy
            .governance
            .severity
            .get(code.as_str())
            .copied()
            .map_or_else(
                || code.default_severity(),
                |s| s.max(code.default_severity()),
            );
        self.out.push(Finding {
            code,
            severity,
            rule_refs: refs,
            message,
            fix,
        });
    }

    fn finish(mut self) -> Vec<Finding> {
        self.out.sort_by(|a, b| {
            (a.rule_refs.first(), a.code, &a.rule_refs, &a.message).cmp(&(
                b.rule_refs.first(),
                b.code,
                &b.rule_refs,
                &b.message,
            ))
        });
        self.out.dedup();
        self.out
    }

    fn governance(&self) -> bool {
        crate::validate::governance_mode(self.doc)
    }

    /// Whether the rule's set is exempt from governance and reviews: only
    /// the managed `system_baseline` the engine built.
    fn exempt(&self, set: &RuleSet) -> bool {
        self.exempt == Some(set.id)
    }

    /// The checks of one rule on its own.
    fn rule_checks(&mut self, e: &Entry<'_>) {
        let rule = e.rule;
        let kind = rule.action.kind();
        let me = vec![e.r()];
        let g = &self.doc.policy.governance;

        // Lifecycle.
        match activity(rule, &self.clock) {
            // An expired `convert_to_audit` rule still records matches:
            // removing it would lose that audit trail, so it is reported
            // without a fix.
            Activity::Expired if rule.on_expire == crate::model::OnExpire::ConvertToAudit => self
                .push(
                    FindingCode::ExpiredRulePresent,
                    me.clone(),
                    format!(
                        "expired at {}; it no longer decides, but still audits its matches (`on_expire: convert_to_audit`)",
                        rule.expires_at.map_or_else(String::new, |t| t.to_string())
                    ),
                    None,
                ),
            Activity::Expired => self.push(
                FindingCode::ExpiredRulePresent,
                me.clone(),
                format!(
                    "expired at {}; it no longer decides",
                    rule.expires_at.map_or_else(String::new, |t| t.to_string())
                ),
                Some(Fix::RemoveRule),
            ),
            Activity::Active => {
                if let Some(e_at) = rule.expires_at
                    && self
                        .now
                        .plus_days(i64::from(g.expiring_soon_days))
                        .is_some_and(|soon| e_at <= soon)
                    {
                        self.push(
                            FindingCode::ExpiringSoon,
                            me.clone(),
                            format!("expires at {e_at}"),
                            None,
                        );
                    }
            }
            Activity::Disabled | Activity::NotYetActive => {}
        }
        if rule.enabled && !self.exempt(e.set) {
            if let Some(due) = review_by(&rule.metadata, Some(kind))
                && due < self.now.date()
            {
                self.push(
                    FindingCode::ReviewOverdue,
                    me.clone(),
                    format!("review was due on {due}"),
                    None,
                );
            }
            // A trust source grants rather than decides, so its use is not
            // counted as a hit (#9 reports grants).
            let usage = self
                .facts
                .usage
                .get(&rule.id)
                .filter(|_| kind != ActionKind::TrustSource);
            if let Some(u) = usage {
                let window = self.now.plus_days(-i64::from(g.stale_after_days));
                let old = window.is_some_and(|w| {
                    u.last_matched_at.is_none_or(|t| t < w)
                        && rule.metadata.created_at.is_none_or(|c| c < w)
                });
                if old && u.devices_online {
                    self.push(
                        FindingCode::StaleRule,
                        me.clone(),
                        format!(
                            "no match in {} days while devices in scope were online",
                            g.stale_after_days
                        ),
                        Some(Fix::ConvertToAudit),
                    );
                }
            }
        }

        // Identity.
        if kind.permits() {
            match weakest_identity(&rule.match_) {
                Guaranteed::None | Guaranteed::WeakHash | Guaranteed::Weak => self.push(
                    FindingCode::WeakIdentity,
                    me.clone(),
                    "this allow identifies objects only by a file name, metadata, an extension, or SHA-1 or MD5; anyone can produce such a file".to_owned(),
                    Some(Fix::Narrow { hint: "add a SHA-256, or a publisher with a product name" }),
                ),
                Guaranteed::Path => {
                    let flagged = self.flagged_path(&rule.match_);
                    if let Some(dir) = flagged {
                        self.push(
                            FindingCode::UserWritablePathAllow,
                            me.clone(),
                            format!("this allow trusts the path `{dir}`, which the writable-path scanner flagged as writable by non-administrators"),
                            Some(Fix::Narrow { hint: "replace the path with a hash or publisher identity" }),
                        );
                    } else {
                        self.push(
                            FindingCode::WeakIdentity,
                            me.clone(),
                            "this allow identifies objects only by their path; it is only as safe as the path's ACL".to_owned(),
                            Some(Fix::Narrow { hint: "add a hash or a publisher" }),
                        );
                    }
                }
                Guaranteed::Publisher => {
                    if let Some(p) = self.restricted_publisher_only(&rule.match_) {
                        self.push(
                            FindingCode::RestrictedPublisherBroad,
                            me.clone(),
                            format!("this allow trusts everything `{p}` signs; that publisher's binaries include tools that run arbitrary code"),
                            Some(Fix::Narrow { hint: "add a product or file-name constraint" }),
                        );
                    }
                }
                Guaranteed::Strong => {}
            }
        }
        self.signers(e);
        self.patterns(e);
        self.principals(e);

        // Metadata dated in the future: a creation, approval or review that
        // has not happened yet, which could stretch a review or an
        // exception's year.
        if rule.enabled {
            let m = &rule.metadata;
            for (field, at) in [
                ("approved_at", m.approved_at),
                ("created_at", m.created_at),
                ("last_reviewed_at", m.last_reviewed_at),
            ] {
                if let Some(at) = at.filter(|t| *t > self.now) {
                    self.push(
                        FindingCode::FutureDatedMetadata,
                        me.clone(),
                        format!("`{field}` ({at}) is in the future"),
                        Some(Fix::AddMetadata {
                            fields: vec![field],
                        }),
                    );
                }
            }
        }

        // Governance, as validation applies it: not to the managed
        // `system_baseline` the engine built.
        if self.governance() && rule.enabled && !self.exempt(e.set) {
            let exception = is_exception(rule);
            let needs_justification = kind.permits()
                || matches!(kind, ActionKind::TrustSource | ActionKind::Ignore)
                || exception;
            if needs_justification
                && rule
                    .metadata
                    .justification
                    .as_deref()
                    .is_none_or(|j| j.trim().is_empty())
            {
                self.push(
                    FindingCode::MissingJustification,
                    me.clone(),
                    format!("governance mode needs a justification for this `{kind}` rule"),
                    Some(Fix::AddMetadata {
                        fields: vec!["justification"],
                    }),
                );
            }
            if exception {
                let mut missing = Vec::new();
                let start = crate::lifecycle::exception_start(&rule.metadata);
                match (rule.expires_at, start) {
                    (None, None) => missing.extend(["expires_at", "approved_at"]),
                    (None, Some(_)) => missing.push("expires_at"),
                    (Some(_), None) => missing.push("approved_at"),
                    (Some(t), Some(start)) => {
                        // From no later than now, so an approval dated in
                        // the future cannot stretch the year.
                        let start = start.min(self.now);
                        if start.plus_days(MAX_EXCEPTION_DAYS).is_none_or(|l| t > l) {
                            missing.push("expires_at (at most 365 days)");
                        }
                    }
                }
                if rule.metadata.approved_by.is_none() {
                    missing.push("approved_by");
                }
                if rule.metadata.risk_rating.is_none() {
                    missing.push("risk_rating");
                }
                if !missing.is_empty() {
                    self.push(
                        FindingCode::ExceptionWithoutExpiry,
                        me.clone(),
                        format!(
                            "this rule is an exception; governance mode needs {}",
                            missing.join(", ")
                        ),
                        Some(Fix::AddMetadata { fields: missing }),
                    );
                }
            }
            if needs_review(kind) && review_by(&rule.metadata, Some(kind)).is_none() {
                self.push(
                    FindingCode::MissingJustification,
                    me,
                    "governance mode needs a review date: set `review_by` or `created_at`"
                        .to_owned(),
                    Some(Fix::AddMetadata {
                        fields: vec!["review_by"],
                    }),
                );
            }
        }
    }

    /// A scanner-flagged directory that some way the tree can match trusts:
    /// a branch whose path criterion can match a file in that directory.
    /// A pattern is checked against a file under the directory; a literal
    /// by prefix in either direction (a path above the directory covers
    /// it). A tree too wide to expand is checked as if every path test
    /// were required.
    fn flagged_path(&self, tree: &Match) -> Option<String> {
        if self.facts.writable_dirs.is_empty() {
            return None;
        }
        let flagged: Vec<String> = self
            .facts
            .writable_dirs
            .iter()
            .map(|d| palisade_core::path::normalize(d).as_str().to_owned())
            .collect();
        let paths: Vec<&Criterion> = identity::literals(tree)
            .into_iter()
            .filter(|(c, positive)| {
                *positive
                    && c.operator.is_positive()
                    && matches!(c.field, Field::PathFull | Field::PathDirectory)
            })
            .map(|(c, _)| c)
            .collect();
        for c in paths {
            for d in &flagged {
                if path_test_reaches(c, d) {
                    return Some(d.clone());
                }
            }
        }
        None
    }

    /// The restricted publisher that some way the tree can match trusts
    /// with nothing else narrowing it: a branch whose positive criteria
    /// name a restricted publisher and test no product, file name, full
    /// path or hash. A test under `not` excludes files and narrows nothing.
    /// A tree too wide to expand is reported if it names a restricted
    /// publisher at all.
    fn restricted_publisher_only(&self, tree: &Match) -> Option<String> {
        if self.facts.restricted_publishers.is_empty() {
            return None;
        }
        // Each restricted publisher as a validly signed object's facts, so
        // a publisher criterion is tested as the evaluator tests it: with
        // its operator and options (`starts_with "Example"` names
        // `Example Ltd`), not by comparing values. A result the bare
        // signer cannot settle (a signer option it has no fact for) could
        // match, so it counts.
        let objects: Vec<(&String, crate::facts::ObjectFacts)> = self
            .facts
            .restricted_publishers
            .iter()
            .map(|p| {
                let mut signer = crate::facts::SignerFact::new(
                    crate::facts::SignerStatus::Valid,
                    crate::facts::SignatureSource::Embedded,
                );
                signer.publisher = Some(p.clone());
                (
                    p,
                    crate::facts::ObjectFacts::new().with_signers(vec![signer]),
                )
            })
            .collect();
        let variables = crate::facts::PathVariables::new();
        let context = crate::context::EvaluationContext::new();
        let ctx = crate::ops::EvalContext {
            action: ActionKind::Allow,
            variables: &variables,
            context: &context,
        };
        let named = |c: &Criterion| {
            if c.field != Field::SignerPublisher || !c.operator.is_positive() {
                return None;
            }
            let compiled = crate::ops::CompiledCriterion::compile(c).ok()?;
            objects
                .iter()
                .find(|(_, facts)| compiled.eval(facts, &ctx).result != crate::ops::Tri::NoMatch)
                .map(|(p, _)| (*p).clone())
        };
        let narrows = |c: &Criterion| {
            matches!(
                c.field,
                Field::MetaProductName
                    | Field::MetaOriginalFilename
                    | Field::MetaInternalName
                    | Field::PathFileName
                    | Field::PathFull
            ) || matches!(c.field.class(), FieldClass::Hash { .. })
                || c.field == Field::SignerLeafThumbprint
        };
        match identity::branches(tree) {
            Some(branches) => branches.iter().find_map(|b| {
                if b.iter().any(|c| narrows(c)) {
                    None
                } else {
                    b.iter().find_map(|c| named(c))
                }
            }),
            None => identity::literals(tree)
                .into_iter()
                .filter(|(_, positive)| *positive)
                .find_map(|(c, _)| named(c)),
        }
    }

    fn signers(&mut self, e: &Entry<'_>) {
        if self.facts.certificates.is_empty() || !e.rule.action.kind().needs_identity() {
            return;
        }
        let certs: BTreeMap<String, CertificateState> = self
            .facts
            .certificates
            .iter()
            .map(|(k, v)| {
                (
                    crate::ops::normalize_hex(k)
                        .filter(|h| h.len() == 64)
                        .unwrap_or_else(|| crate::ops::fold(k, false)),
                    *v,
                )
            })
            .collect();
        // Only a signer the rule trusts: a positive test outside `not`.
        for (c, positive) in identity::literals(&e.rule.match_) {
            if !positive || !c.operator.is_positive() {
                continue;
            }
            for v in &c.values {
                let key = match c.field {
                    Field::SignerPublisher => crate::ops::fold(v, false),
                    Field::SignerLeafThumbprint => crate::ops::normalize_hex(v).unwrap_or_default(),
                    _ => continue,
                };
                if let Some(state) = certs.get(&key) {
                    let what = match state {
                        CertificateState::Revoked => "revoked",
                        CertificateState::Expired => "expired",
                    };
                    self.push(
                        FindingCode::RevokedOrExpiredSigner,
                        vec![e.r()],
                        format!("this rule trusts `{v}`, whose certificate is {what}; files it signs no longer match a trusted signature"),
                        Some(Fix::Narrow { hint: "replace the signer with hashes of the files still needed" }),
                    );
                    return;
                }
            }
        }
    }

    /// `broad_wildcard` and `regex_cost`. Each is reported at most once
    /// per rule, independently.
    fn patterns(&mut self, e: &Entry<'_>) {
        let literals = identity::literals(&e.rule.match_);
        if let Some((c, _)) = literals.iter().find(|(c, _)| {
            matches!(c.operator, Operator::Regex | Operator::NotRegex)
                && c.values
                    .iter()
                    .any(|v| regex_near_limit(v, c.case_sensitive.unwrap_or(false)))
        }) {
            let _ = c;
            self.push(
                FindingCode::RegexCost,
                vec![e.r()],
                format!("a regular expression compiles to more than half the engine's limit of {REGEX_SIZE_LIMIT} bytes; matching it is slow and a small edit can push it over"),
                Some(Fix::Narrow { hint: "simplify the expression or use several values" }),
            );
        }
        if !e.rule.action.kind().needs_identity() {
            return;
        }
        // Only a pattern that lets objects in: a positive test outside
        // `not`. An excluded pattern makes the rule narrower.
        for (c, positive) in literals {
            if !positive
                || !c.operator.is_positive()
                || !matches!(c.field.class(), FieldClass::Path)
            {
                continue;
            }
            if c.operator == Operator::Wildcard
                && let Some(v) = c.values.iter().find(|v| is_broad_path_wildcard(v))
            {
                self.push(
                    FindingCode::BroadWildcard,
                    vec![e.r()],
                    format!("`{v}` matches almost every file"),
                    Some(Fix::Narrow {
                        hint: "name a specific directory",
                    }),
                );
                return;
            }
            if matches!(c.operator, Operator::Wildcard | Operator::Regex)
                && !self.facts.path_corpus.is_empty()
                && let Some(share) = corpus_share(c, &self.facts.path_corpus)
                && share >= u64::from(self.options.broad_corpus_percent)
            {
                self.push(
                    FindingCode::BroadWildcard,
                    vec![e.r()],
                    format!("this pattern matches {share}% of the sample paths"),
                    Some(Fix::Narrow {
                        hint: "name a specific directory",
                    }),
                );
                return;
            }
        }
    }

    /// `duplicate_principal`: a principal that a rule both requires and
    /// excludes, or lists twice on the same field. Polarity is the
    /// operator's, flipped under each `not`.
    fn principals(&mut self, e: &Entry<'_>) {
        let mut include: BTreeMap<Field, BTreeSet<String>> = BTreeMap::new();
        let mut exclude: BTreeMap<Field, BTreeSet<String>> = BTreeMap::new();
        for (c, positive) in identity::literals(&e.rule.match_) {
            if !matches!(
                c.field.class(),
                FieldClass::PrincipalSet | FieldClass::Sid | FieldClass::PrincipalName
            ) {
                continue;
            }
            let side = if positive { &mut include } else { &mut exclude };
            let set = side.entry(c.field).or_default();
            for v in &c.values {
                if !set.insert(principal_key(v)) {
                    self.push(
                        FindingCode::DuplicatePrincipal,
                        vec![e.r()],
                        format!("`{v}` is listed more than once"),
                        None,
                    );
                    return;
                }
            }
        }
        for (field, inc) in &include {
            if let Some(exc) = exclude.get(field)
                && let Some(p) = inc.intersection(exc).next()
            {
                self.push(
                    FindingCode::DuplicatePrincipal,
                    vec![e.r()],
                    format!("`{p}` is both included and excluded"),
                    None,
                );
                return;
            }
        }
    }

    /// `duplicate_rule`: rules with the same normalised match, action,
    /// object types, enforcement, mode, activity window and expiry
    /// behaviour, so they mean the same. Each group is reported once, on
    /// every rule but the one that keeps deciding: the first under
    /// `first_match` and `priority` (by the model's own order), otherwise
    /// the lowest rule ID. So the result does not depend on rule order, and
    /// removing the reported rules changes no decision.
    fn duplicates(&mut self, entries: &[Entry<'_>]) {
        let model = self.doc.policy.precedence_model;
        let mut groups: BTreeMap<String, Vec<&Entry<'_>>> = BTreeMap::new();
        for e in entries {
            let Ok(key) = serde_json::to_string(&(
                normalized(&e.rule.match_),
                &e.rule.action,
                sorted_types(e.rule),
                e.rule.enforcement_override,
                e.set.mandatory,
                e.set.mode_override,
                (e.rule.activates_at, e.rule.expires_at, e.rule.on_expire),
                // Under the ordered models, position matters too.
                match model {
                    PrecedenceModel::FirstMatch => (e.rule.order.map(i64::from), e.set.read_only),
                    PrecedenceModel::Priority => (e.rule.priority.map(i64::from), false),
                    _ => (None, false),
                },
                e.scopes(self.doc),
            )) else {
                continue;
            };
            groups.entry(key).or_default().push(e);
        }
        for group in groups.values_mut().filter(|g| g.len() > 1) {
            group.sort_by_key(|e| e.r());
            let keep = group[0].r();
            for e in &group[1..] {
                self.push(
                    FindingCode::DuplicateRule,
                    vec![e.r(), keep],
                    "this rule has the same match, action, scope and timing as another".to_owned(),
                    Some(Fix::RemoveRule),
                );
            }
        }
    }

    /// `shadowed`, `contradiction` and `ineffective_vs_mandatory`.
    fn conflicts(&mut self, entries: &[Entry<'_>]) {
        // Only pairs that can be proven are compared. If `cover` covers
        // `victim`, then every criterion `cover` requires (one that every
        // match of `cover` must satisfy) is implied by a criterion of
        // `victim` on the same field, with a value among the required
        // criterion's values ([`subsume::criterion_covers`]). So each rule
        // is filed as a cover under the keys of one required criterion,
        // and looked up as a victim by the keys of all its criteria. A
        // rule that requires no criterion is compared with every rule.
        let mut covers_by_key: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut broad: Vec<usize> = Vec::new();
        for (j, e) in entries.iter().enumerate() {
            match identity::best_required(&e.rule.match_) {
                Some(c) => {
                    for k in cover_keys(c) {
                        covers_by_key.entry(k).or_default().push(j);
                    }
                }
                None => broad.push(j),
            }
        }
        // Pairs are checked as they are found, never collected, and each
        // victim is compared with at most `MAX_CANDIDATES` covers, most
        // selective keys first: a check that gives up only misses findings,
        // which the conservative design allows.
        let mut reported: BTreeSet<(FindingCode, usize)> = BTreeSet::new();
        let mut budget = self.options.max_pair_checks;
        for (i, e) in entries.iter().enumerate() {
            let Some(others) = candidates(&e.rule.match_, &covers_by_key, &broad, &mut budget)
            else {
                return;
            };
            for j in others {
                if j == i {
                    continue;
                }
                if budget == 0 {
                    return;
                }
                budget -= 1;
                self.conflict(entries, &mut reported, i, j);
            }
        }
    }

    /// Checks whether `entries[j]` makes `entries[i]` shadowed,
    /// ineffective or contradicted.
    fn conflict(
        &mut self,
        entries: &[Entry<'_>],
        reported: &mut BTreeSet<(FindingCode, usize)>,
        i: usize,
        j: usize,
    ) {
        let model = self.doc.policy.precedence_model;
        {
            // Does `cover` (j) always match when `victim` (i) does?
            let (victim, cover) = (&entries[i], &entries[j]);
            // A scoped rule applies only inside its scope (#38). Scopes are
            // not compared, so a pair is only proven when both rules are in
            // exactly the same scopes.
            if cover.scopes(self.doc) != victim.scopes(self.doc) {
                return;
            }
            if !always_matches(cover, victim) {
                return;
            }
            // A deny that matches on unknown facts is not a plain match.
            let cover_mandatory =
                cover.set.mandatory && matches!(cover.rule.action, Action::Deny(_));
            let Some(v) = victim.verdict().filter(|_| !victim.set.mandatory) else {
                return;
            };
            if cover_mandatory && v.allows() {
                if reported.insert((FindingCode::IneffectiveVsMandatory, i)) {
                    self.push(
                        FindingCode::IneffectiveVsMandatory,
                        vec![victim.r(), cover.r()],
                        "a mandatory deny always blocks what this allow matches, so it never lets anything run".to_owned(),
                        Some(Fix::RemoveRule),
                    );
                }
                return;
            }
            if cover.set.mandatory
                || cover.rule.enforcement_override != victim.rule.enforcement_override
            {
                return;
            }
            // Different modes can make the outranked rule decide (#36).
            if cover.set.mode_override != victim.set.mode_override {
                return;
            }
            let Some(cv) = cover.verdict() else { return };
            let shadowed = match model {
                // Any deny beats every allow, and among denies the most
                // specific, then the lowest rule ID, decides.
                PrecedenceModel::DenyWins => {
                    !cv.allows()
                        && (v.allows()
                            || (
                                crate::precedence::Spec::of(&cover.rule.match_),
                                cover.rule.id,
                            ) < (
                                crate::precedence::Spec::of(&victim.rule.match_),
                                victim.rule.id,
                            ))
                }
                PrecedenceModel::FirstMatch => first_match_before(self.doc, cover, victim),
                _ => false,
            };
            if shadowed {
                if reported.insert((FindingCode::Shadowed, i)) {
                    self.push(
                        FindingCode::Shadowed,
                        vec![victim.r(), cover.r()],
                        format!(
                            "under `{}`, another rule always matches first and decides, so this rule never does",
                            model_name(model)
                        ),
                        Some(Fix::RemoveRule),
                    );
                }
                return;
            }
            if v.allows() != cv.allows() {
                let (a, b) = if victim.r() < cover.r() {
                    (i, j)
                } else {
                    (j, i)
                };
                if reported.insert((
                    FindingCode::Contradiction,
                    a.min(b) * entries.len() + a.max(b),
                )) {
                    self.push(
                        FindingCode::Contradiction,
                        vec![entries[a].r(), entries[b].r()],
                        "an allow and a deny both match some objects; only the precedence model decides between them".to_owned(),
                        None,
                    );
                }
            }
        }
    }

    /// `too_many_hash_rules`, and `vulnerable_version_allowed`.
    fn hash_counts(&mut self) {
        let referenced: Vec<&RuleSet> = crate::lifecycle::referenced(self.doc).collect();
        for set in &referenced {
            let n: usize = set
                .rules
                .iter()
                .flat_map(|r| identity::criteria(&r.match_))
                .filter(|c| matches!(c.field.class(), FieldClass::Hash { .. }))
                .map(|c| c.values.len())
                .sum();
            if n > self.options.max_inline_hashes
                && let Some(first) = set.rules.first()
            {
                self.push(
                        FindingCode::TooManyHashRules,
                        vec![RuleRef { rule_set_id: set.id, rule_id: first.id }],
                        format!("rule set `{}` holds {n} inline hash values; more than {} should be a hash set (#42)", set.name, self.options.max_inline_hashes),
                        None,
                    );
            }
        }
        let clock = self.clock;
        // Vulnerable versions: a deny in a mandatory or curated blocklist
        // with a version test, and an allow whose versions overlap it for
        // the same signer or product.
        let vulnerable: Vec<(&RuleSet, &Rule)> = referenced
            .iter()
            .filter(|s| {
                s.kind == crate::model::RuleSetKind::Blocklist && (s.mandatory || s.read_only)
            })
            .flat_map(|s| s.rules.iter().map(move |r| (*s, r)))
            .filter(|(_, r)| activity(r, &clock).is_active() && matches!(r.action, Action::Deny(_)))
            .collect();
        if vulnerable.is_empty() {
            return;
        }
        // Each deny is filed under the publisher and product names it
        // requires: an allow can only overlap a deny that shares one
        // ([`overlap`]), so it is compared only with those, and each pair
        // costs one unit of the pair budget.
        let mut by_key: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (n, (_, r)) in vulnerable.iter().enumerate() {
            for k in identity_name_keys(&r.match_) {
                by_key.entry(k).or_default().push(n);
            }
        }
        let mut budget = self.options.max_pair_checks;
        for set in &referenced {
            for rule in set
                .rules
                .iter()
                .filter(|r| activity(r, &clock).is_active() && r.action.kind().permits())
            {
                let candidates: BTreeSet<usize> = identity_name_keys(&rule.match_)
                    .iter()
                    .filter_map(|k| by_key.get(k))
                    .flatten()
                    .copied()
                    .collect();
                for (vset, vrule) in candidates.into_iter().map(|n| vulnerable[n]) {
                    if budget == 0 {
                        return;
                    }
                    budget -= 1;
                    let types_meet = rule.object_types.is_empty()
                        || vrule.object_types.is_empty()
                        || rule
                            .object_types
                            .iter()
                            .any(|t| vrule.object_types.contains(t));
                    if !types_meet {
                        continue;
                    }
                    if let Some(range) = overlap(&rule.match_, &vrule.match_) {
                        self.push(
                            FindingCode::VulnerableVersionAllowed,
                            vec![RuleRef { rule_set_id: set.id, rule_id: rule.id }, RuleRef { rule_set_id: vset.id, rule_id: vrule.id }],
                            format!("this allow covers versions {range}, which a blocklist marks vulnerable"),
                            Some(Fix::Narrow { hint: "raise the allowed minimum version" }),
                        );
                        break;
                    }
                }
            }
        }
    }
}

/// The most covers one rule is compared with.
const MAX_CANDIDATES: usize = 512;

/// The covers a victim with `tree` is compared with: at most
/// [`MAX_CANDIDATES`] distinct rules, collected in key order and stopping
/// as soon as the cap is reached, so a huge bucket (one publisher shared
/// by thousands of rules) is never copied. Each index entry looked at
/// costs one unit of `budget`; `None` once it runs out.
fn candidates(
    tree: &Match,
    covers_by_key: &BTreeMap<String, Vec<usize>>,
    broad: &[usize],
    budget: &mut usize,
) -> Option<BTreeSet<usize>> {
    let mut others: BTreeSet<usize> = BTreeSet::new();
    for bucket in victim_keys(tree)
        .iter()
        .filter_map(|k| covers_by_key.get(k).map(Vec::as_slice))
        .chain(core::iter::once(broad))
    {
        for &j in bucket {
            if others.len() >= MAX_CANDIDATES {
                return Some(others);
            }
            *budget = budget.checked_sub(1)?;
            others.insert(j);
        }
    }
    Some(others)
}

/// The model's `snake_case` name.
fn model_name(model: PrecedenceModel) -> &'static str {
    match model {
        PrecedenceModel::DenyWins => "deny_wins",
        PrecedenceModel::AllowWins => "allow_wins",
        PrecedenceModel::Specificity => "specificity",
        PrecedenceModel::FirstMatch => "first_match",
        PrecedenceModel::Priority => "priority",
    }
}

/// Whether `cover` applies, at every time and for every object and
/// context, whenever `victim` does. Conservative:
///
/// - `cover` applies to every object type `victim` does;
/// - `cover` is active whenever `victim` is: its activity window contains
///   `victim`'s, and it fails in the same direction or more openly;
/// - `victim` is not a deny that also applies on unknown or unparseable
///   facts, which `cover` might not;
/// - a rule that needs an identity trusts a path only where users cannot
///   write (#31), so its path tests match less often than a deny's: such
///   a `cover` with a path test is only compared with another rule that
///   needs an identity;
/// - and `cover`'s tree is `Match` whenever `victim`'s is
///   ([`subsume::covers`]).
fn always_matches(cover: &Entry<'_>, victim: &Entry<'_>) -> bool {
    if !cover.applies_to_all_types_of(victim) {
        return false;
    }
    let (c, v) = (cover.rule, victim.rule);
    // `victim`'s window inside `cover`'s, and `cover` no stricter about
    // time: a permissive cover needs both clock readings in its window,
    // which can end it before a deny victim.
    let starts = match (c.activates_at, v.activates_at) {
        (None, _) => true,
        (Some(a), Some(b)) => a <= b,
        (Some(_), None) => false,
    };
    let ends = match (c.expires_at, v.expires_at) {
        (None, _) => true,
        (Some(a), Some(b)) => a >= b,
        (Some(_), None) => false,
    };
    let timed = c.activates_at.is_some() || c.expires_at.is_some();
    let same_direction = c.action.kind().needs_identity() == v.action.kind().needs_identity()
        || !c.action.kind().needs_identity();
    if !starts || !ends || (timed && !same_direction) {
        return false;
    }
    if let Action::Deny(o) = &v.action
        && (o.unknown_as == crate::model::UnknownAs::Match
            || o.on_unparseable == crate::model::UnknownAs::Match)
    {
        return false;
    }
    let path_acl = c.action.kind().needs_identity() && !v.action.kind().needs_identity();
    if path_acl
        && identity::criteria(&c.match_)
            .iter()
            .any(|x| matches!(x.field.class(), FieldClass::Path | FieldClass::FileName))
    {
        return false;
    }
    covers(&c.match_, &v.match_)
}

/// Whether `a` comes before `b` under `first_match`, whatever matches.
fn first_match_before(doc: &PolicyDocument, a: &Entry<'_>, b: &Entry<'_>) -> bool {
    let curated_first = doc.policy.precedence_options.curated_first;
    let key = |e: &Entry<'_>| {
        (
            curated_first && !e.set.read_only,
            e.rule.order.is_none(),
            e.rule.order,
            core::cmp::Reverse(e.rule.id),
        )
    };
    // The managed baseline is a floor (#39): it never comes first.
    !crate::unknown::baseline::is_system_baseline(a.set)
        && (crate::unknown::baseline::is_system_baseline(b.set) || key(a) < key(b))
}

/// The index keys a required criterion of a cover is filed under: one per
/// value for an operator compared by value, or the field alone.
fn cover_keys(c: &Criterion) -> Vec<String> {
    match value_compared(c) {
        true => c.values.iter().map(|v| key(c.field, v)).collect(),
        false => vec![format!("{:?}:*", c.field)],
    }
}

/// The index keys a victim is looked up by: each criterion's field, and
/// each of its values.
fn victim_keys(tree: &Match) -> Vec<String> {
    let mut out = Vec::new();
    for c in identity::criteria(tree) {
        out.push(format!("{:?}:*", c.field));
        out.extend(c.values.iter().map(|v| key(c.field, v)));
    }
    out.sort();
    out.dedup();
    out
}

/// Whether [`subsume::criterion_covers`] compares the criterion's values
/// one by one: every positive operator except version ranges and
/// yes-or-no tests.
fn value_compared(c: &Criterion) -> bool {
    c.operator.is_positive()
        && !matches!(c.field.class(), FieldClass::Version | FieldClass::Bool)
        && !matches!(c.operator, Operator::IsTrue | Operator::IsFalse)
}

/// A value's index key: folded more broadly than any comparison, so equal
/// values always share a key.
fn key(field: Field, v: &str) -> String {
    let v = match field.class() {
        FieldClass::Hash { .. } => crate::ops::normalize_hex(v).unwrap_or_else(|| v.to_owned()),
        _ => crate::ops::fold(&v.replace('/', "\\"), false),
    };
    format!("{field:?}={v}")
}

/// A tree with each criterion's values in a canonical order and form, for
/// comparing rules.
fn normalized(tree: &Match) -> Match {
    match tree {
        Match::All(c) => {
            let mut c: Vec<Match> = c.iter().map(normalized).collect();
            c.sort_by_key(|m| serde_json::to_string(m).unwrap_or_default());
            Match::All(c)
        }
        Match::Any(c) => {
            let mut c: Vec<Match> = c.iter().map(normalized).collect();
            c.sort_by_key(|m| serde_json::to_string(m).unwrap_or_default());
            Match::Any(c)
        }
        Match::Not(c) => Match::Not(Box::new(normalized(c))),
        Match::Ref(r) => Match::Ref(*r),
        Match::Criterion(c) => {
            let mut c: Criterion = c.clone();
            let sensitive = c.case_sensitive.unwrap_or(false);
            c.values = c
                .values
                .iter()
                .map(|v| match c.field.class() {
                    FieldClass::Hash { .. } => {
                        crate::ops::normalize_hex(v).unwrap_or_else(|| v.clone())
                    }
                    // A pattern's text is its meaning (`\w` is not `\W`).
                    _ if matches!(c.operator, Operator::Regex | Operator::NotRegex) => v.clone(),
                    class if class.has_case() && !sensitive => crate::ops::fold(v, false),
                    _ => v.clone(),
                })
                .collect();
            // Two-value operators are positional (`time_between 22:00
            // 06:00` wraps past midnight; `06:00 22:00` does not), so their
            // order is kept. Every other operator's values are a set.
            if c.operator.value_count() != (2, 2) {
                c.values.sort();
                c.values.dedup();
            }
            c.case_sensitive = Some(sensitive).filter(|s| *s);
            Match::Criterion(c)
        }
    }
}

fn sorted_types(rule: &Rule) -> Vec<String> {
    let mut t: Vec<String> = rule.object_types.iter().map(ToString::to_string).collect();
    t.sort();
    t
}

fn principal_key(v: &str) -> String {
    crate::context::normalize_sid(v).unwrap_or_else(|| v.to_ascii_lowercase())
}

/// Whether a path wildcard matches almost everything: it fixes no
/// directory below its root (`C:\*`, `*\*.exe`, `**`, `\\server\share\**`),
/// or it fixes at most one and has a `**` anywhere (`C:\**\*.exe`,
/// `%WINDIR%\**`, `C:\Windows\**.exe`). The value is read as matching
/// reads it: normalised, with a path variable counted at its default
/// depth ([`crate::precedence`]).
fn is_broad_path_wildcard(v: &str) -> bool {
    let depth = crate::precedence::path_depth(v, Operator::Wildcard);
    depth == 0 || (depth <= 1 && v.contains("**"))
}

/// The share of `corpus`, in percent, that a path criterion matches.
fn corpus_share(c: &Criterion, corpus: &[String]) -> Option<u64> {
    let compiled = crate::ops::CompiledCriterion::compile(c).ok()?;
    let variables = crate::facts::PathVariables::new();
    let context = crate::context::EvaluationContext::new();
    let ctx = crate::ops::EvalContext {
        action: ActionKind::Deny,
        variables: &variables,
        context: &context,
    };
    let vm = palisade_core::path::VolumeMap::new();
    let hits = corpus
        .iter()
        .filter(|p| {
            let facts = crate::facts::ObjectFacts::new()
                .with_path(crate::facts::PathFact::new(p, &vm).with_user_writable(false));
            compiled.eval(&facts, &ctx).result == crate::ops::Tri::Match
        })
        .count();
    let n = u64::try_from(corpus.len()).ok().filter(|n| *n > 0)?;
    u64::try_from(hits).ok().map(|h| h.saturating_mul(100) / n)
}

/// Whether a positive path criterion can match a file in the directory
/// `dir` (normalised): a literal by prefix in either direction, or a
/// pattern that matches a file in `dir` or whose fixed part lies under it.
fn path_test_reaches(c: &Criterion, dir: &str) -> bool {
    let fold = |v: &str| crate::ops::fold(v, false);
    let d = fold(dir.trim_end_matches('\\'));
    let under = |a: &str, b: &str| {
        a.strip_prefix(b)
            .is_some_and(|r| r.is_empty() || r.starts_with('\\'))
    };
    match c.operator {
        Operator::Equals | Operator::StartsWith => c.values.iter().any(|v| {
            let v = fold(
                palisade_core::path::normalize(v)
                    .as_str()
                    .trim_end_matches('\\'),
            );
            under(&v, &d) || (c.operator == Operator::StartsWith && under(&d, &v))
        }),
        Operator::Wildcard | Operator::Regex => {
            let Ok(compiled) = crate::ops::CompiledCriterion::compile(c) else {
                return false;
            };
            let variables = crate::facts::PathVariables::new();
            let context = crate::context::EvaluationContext::new();
            let ctx = crate::ops::EvalContext {
                action: ActionKind::Deny,
                variables: &variables,
                context: &context,
            };
            let probe = format!("{}\\probe.exe", dir.trim_end_matches('\\'));
            let facts = crate::facts::ObjectFacts::new().with_path(
                crate::facts::PathFact::new(&probe, &palisade_core::path::VolumeMap::new())
                    .with_user_writable(false),
            );
            if compiled.eval(&facts, &ctx).result == crate::ops::Tri::Match {
                return true;
            }
            // The fixed part of a wildcard below the directory.
            c.operator == Operator::Wildcard
                && c.values.iter().any(|v| {
                    let n = palisade_core::path::normalize(v);
                    let text = n.as_str();
                    let cut = text.find(['*', '?', '[']).unwrap_or(text.len());
                    let fixed = fold(text[..cut].trim_end_matches('\\'));
                    !fixed.is_empty() && under(&fixed, &d)
                })
        }
        _ => false,
    }
}

/// Whether a regular expression compiles within the engine's size limit
/// but not within half of it, with the engine's own measure (#32).
fn regex_near_limit(pattern: &str, case_sensitive: bool) -> bool {
    // `Some(true)`: it builds; `Some(false)`: too large; `None`: another
    // error, which validation reports.
    let builds = |limit: usize| match regex_automata::meta::Regex::builder()
        .syntax(regex_automata::util::syntax::Config::new().case_insensitive(!case_sensitive))
        .configure(
            regex_automata::meta::Regex::config()
                .nfa_size_limit(Some(limit))
                .backtrack(false),
        )
        .build(pattern)
    {
        Ok(_) => Some(true),
        Err(e) if e.size_limit().is_some() => Some(false),
        Err(_) => None,
    };
    builds(REGEX_SIZE_LIMIT / 2) == Some(false) && builds(REGEX_SIZE_LIMIT) == Some(true)
}

/// The versions an allow covers that a vulnerable deny also covers. Both
/// trees must require the same publisher or product, and must not
/// require disjoint values of any other identity field (product name,
/// file names, hashes). On each version field, a tree's versions are the
/// intersection of every version criterion it requires (a union over the
/// values of one criterion). Conservative: an `any` or a criterion it
/// cannot read leaves a tree's versions unbounded, but only when the
/// trees share an identity, which keeps the finding to the same product.
fn overlap(allow: &Match, deny: &Match) -> Option<String> {
    let ra = identity::required_all(allow);
    let rd = identity::required_all(deny);
    let values = |cs: &[&Criterion], field: Field| -> Option<BTreeSet<String>> {
        let sets: Vec<BTreeSet<String>> = cs
            .iter()
            .filter(|c| c.field == field && c.operator == Operator::Equals)
            .map(|c| c.values.iter().map(|v| key(field, v)).collect())
            .collect();
        sets.into_iter()
            .reduce(|a, b| a.intersection(&b).cloned().collect())
    };
    let shared = |field: Field| match (values(&ra, field), values(&rd, field)) {
        (Some(a), Some(d)) => Some(!a.is_disjoint(&d)),
        _ => None,
    };
    if shared(Field::SignerPublisher) != Some(true) && shared(Field::MetaProductName) != Some(true)
    {
        return None;
    }
    for field in [
        Field::MetaProductName,
        Field::MetaOriginalFilename,
        Field::MetaInternalName,
        Field::PathFileName,
        Field::HashSha256,
        Field::SignerLeafThumbprint,
    ] {
        if shared(field) == Some(false) {
            return None;
        }
    }
    // The deny must say which versions are vulnerable: a deny with no
    // version test is not a vulnerable-version entry, and the allow alone
    // is no evidence. Every field either side constrains must overlap, so
    // a file-version overlap with disjoint product versions is none.
    let mut evidence = None;
    for field in [Field::MetaFileVersion, Field::MetaProductVersion] {
        let a = versions(&ra, field);
        let d = versions(&rd, field);
        if a.is_none() && d.is_none() {
            continue;
        }
        let full = vec![(0u64, u64::MAX)];
        let constrained_by_deny = d.is_some();
        let a = a.unwrap_or_else(|| full.clone());
        let d = d.unwrap_or(full);
        let shared = a.iter().find_map(|(allow_lo, allow_hi)| {
            d.iter().find_map(|(deny_lo, deny_hi)| {
                let lo = (*allow_lo).max(*deny_lo);
                let hi = (*allow_hi).min(*deny_hi);
                (lo <= hi).then_some((lo, hi))
            })
        });
        let (lo, hi) = shared?;
        if constrained_by_deny && evidence.is_none() {
            evidence = Some(format!("{} to {}", show(lo), show(hi)));
        }
    }
    evidence
}

/// The publisher and product names a tree requires, as index keys: an
/// allow and a deny can only overlap in [`overlap`] if they share one.
fn identity_name_keys(tree: &Match) -> Vec<String> {
    let mut out: Vec<String> = identity::required_all(tree)
        .into_iter()
        .filter(|c| {
            c.operator == Operator::Equals
                && matches!(c.field, Field::SignerPublisher | Field::MetaProductName)
        })
        .flat_map(|c| c.values.iter().map(|v| key(c.field, v)))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The versions on `field` that every match of the criteria allows, as
/// closed intervals (empty when none can match); `None` if no criterion
/// constrains the field.
fn versions(cs: &[&Criterion], field: Field) -> Option<Vec<(u64, u64)>> {
    let mut out: Option<Vec<(u64, u64)>> = None;
    for c in cs.iter().filter(|c| c.field == field) {
        let Some(these) = version_ranges(c) else {
            continue;
        };
        out = Some(match out {
            None => these,
            Some(prev) => prev
                .iter()
                .flat_map(|(a, b)| {
                    these.iter().filter_map(move |(c, d)| {
                        let lo = (*a).max(*c);
                        let hi = (*b).min(*d);
                        (lo <= hi).then_some((lo, hi))
                    })
                })
                .collect(),
        });
    }
    out
}

fn as_u64(v: crate::ops::Version) -> u64 {
    v.0.iter().fold(0u64, |acc, p| (acc << 16) | u64::from(*p))
}

fn show(n: u64) -> String {
    let p = |s: u32| (n >> s) & 0xffff;
    format!("{}.{}.{}.{}", p(48), p(32), p(16), p(0))
}

/// The versions one criterion allows, as closed intervals: a union over
/// its values, empty when no version can match (`version_lt 0.0.0.0`,
/// `version_gt` the largest version, or a reversed `version_between`).
/// `None` if it is not a version test this reads.
fn version_ranges(c: &Criterion) -> Option<Vec<(u64, u64)>> {
    let v = |s: &String| crate::ops::Version::parse_strict(s).map(as_u64);
    let one = |i: usize| c.values.get(i).and_then(v);
    Some(match c.operator {
        Operator::VersionEq | Operator::Equals => c
            .values
            .iter()
            .map(|s| v(s).map(|x| (x, x)))
            .collect::<Option<Vec<_>>>()?,
        Operator::VersionGe => vec![(one(0)?, u64::MAX)],
        Operator::VersionGt => one(0)?
            .checked_add(1)
            .map(|lo| (lo, u64::MAX))
            .into_iter()
            .collect(),
        Operator::VersionLe => vec![(0, one(0)?)],
        Operator::VersionLt => one(0)?
            .checked_sub(1)
            .map(|hi| (0, hi))
            .into_iter()
            .collect(),
        Operator::VersionBetween => {
            let (lo, hi) = (one(0)?, one(1)?);
            if lo <= hi { vec![(lo, hi)] } else { Vec::new() }
        }
        _ => return None,
    })
}

/// The outcome of [`publish_gate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gate {
    /// No `error` finding: the bundle may be compiled.
    Pass,
    /// `error` findings, overridden by a tenant administrator with a reason.
    Overridden {
        /// Who overrode.
        actor: String,
        /// Why.
        reason: String,
        /// The findings overridden.
        findings: Vec<Finding>,
    },
    /// `error` findings block publishing.
    Blocked(Vec<Finding>),
}

/// A tenant administrator's override of `error` findings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Override {
    /// The administrator.
    pub actor: String,
    /// Why. Must not be empty.
    pub reason: String,
}

/// Whether a bundle may be compiled from `findings` (#40): `error`
/// findings block it, unless `admin` overrides them with a reason.
#[must_use]
pub fn publish_gate(findings: &[Finding], admin: Option<&Override>) -> Gate {
    let errors: Vec<Finding> = findings
        .iter()
        .filter(|f| f.severity == FindingSeverity::Error)
        .cloned()
        .collect();
    if errors.is_empty() {
        return Gate::Pass;
    }
    match admin.filter(|o| !o.reason.trim().is_empty() && !o.actor.trim().is_empty()) {
        Some(o) => Gate::Overridden {
            actor: o.actor.clone(),
            reason: o.reason.trim().to_owned(),
            findings: errors,
        },
        None => Gate::Blocked(errors),
    }
}

/// The review date of a rule, as the analysis uses it.
#[must_use]
pub fn due(rule: &Rule) -> Option<Date> {
    review_by(&rule.metadata, Some(rule.action.kind()))
}

#[cfg(test)]
mod tests;
