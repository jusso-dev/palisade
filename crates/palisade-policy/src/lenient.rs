//! The lenient reader: policy documents of a newer minor version (#30,
//! #330).
//!
//! A minor version only adds optional fields. A reader built for an older
//! minor does not know them. [`PolicyDocument::from_json`] (strict mode,
//! the default and the only mode for authoring) rejects them. [`read_json`]
//! reads the document anyway, but only where that cannot relax a decision
//! (ADR 0018). An unknown field has no known meaning, so the reader cannot
//! tell whether it would have restricted something. It therefore only skips
//! what never decides:
//!
//! - **Governance data.** A field of a `metadata` object (the policy's,
//!   a rule set's or a rule's), or of the policy's `governance` settings,
//!   that is unknown or whose value cannot be read is set aside. Metadata
//!   never changes a decision ([`PolicyDocument::decision_relevant`]), and
//!   governance settings only steer review and publishing.
//! - **Rules that never let an object run.** A rule that cannot be read,
//!   for example because its match tree tests a criterion this reader does
//!   not know, is unreadable. If its action is `audit`, `defer`,
//!   `trust_source` or `ignore`, the rule is set aside. Without it, nothing
//!   that was blocked can run: an annotation or a trust grant is lost, or
//!   an excluded object is decided by the policy instead.
//!
//! Every other unreadable part refuses the whole document
//! ([`LenientError`]), and the device keeps the policy it has (ADR 0018,
//! "new bundle fails verification or activation"). That covers an unknown
//! field anywhere else, and an unreadable rule that allows, denies, or has
//! an action this reader does not know. The reader cannot drop such a rule
//! without risking a relaxation: without a deny, the object may run.
//! Without an `allow_contained`, a plain `allow` may win in its place.
//! Without a plain `allow`, an `allow_elevated` may.
//!
//! What is set aside is kept, with its JSON Pointer and value, in
//! [`Lenient::ignored`], so a caller can report it.
//!
//! Documents of an older major version are migrated first
//! ([`crate::migrate`]).

use core::fmt;

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::migrate::{self, MigrateError, UniqueValue};
use crate::model::{ActionKind, GovernanceSettings, Metadata, PolicyDocument, SchemaVersion};

/// A document read by [`read_json`].
#[derive(Clone, Debug, PartialEq)]
pub struct Lenient {
    /// The readable document, in the current version.
    pub document: PolicyDocument,
    /// The version it was written for.
    pub from: SchemaVersion,
    /// What was set aside, in document order.
    pub ignored: Vec<Ignored>,
}

/// One part of a document that [`read_json`] set aside.
#[derive(Clone, Debug, PartialEq)]
pub struct Ignored {
    /// JSON Pointer (RFC 6901) of the part, in the document in the current
    /// version (after any migration).
    pub pointer: String,
    /// What it is.
    pub kind: IgnoredKind,
    /// The part, unchanged.
    pub value: Value,
    /// Why it could not be read.
    pub reason: String,
}

/// What kind of part was set aside.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IgnoredKind {
    /// A field of a `metadata` or `governance` object.
    GovernanceField,
    /// A rule that cannot be read, and never lets an object run.
    Rule(ActionKind),
}

/// A document could not be read, even leniently.
#[derive(Debug)]
pub enum LenientError {
    /// The input is not JSON, has no supported version, cannot be migrated,
    /// or has an unknown or unreadable part outside the governance data and
    /// the rules.
    Read(MigrateError),
    /// A rule cannot be read, and setting it aside could relax a decision.
    UnreadableRule {
        /// JSON Pointer of the rule.
        pointer: String,
        /// Its action, if this reader knows it.
        action: Option<ActionKind>,
        /// Why it cannot be read.
        reason: String,
    },
}

impl fmt::Display for LenientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(e) => e.fmt(f),
            Self::UnreadableRule {
                pointer,
                action,
                reason,
            } => {
                write!(f, "{pointer}: ")?;
                match action {
                    Some(a) => write!(f, "an unreadable `{}` rule", a.as_str())?,
                    None => f.write_str("an unreadable rule with an unknown action")?,
                }
                write!(
                    f,
                    " could relax a decision, so the document is refused: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for LenientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(e) => Some(e),
            Self::UnreadableRule { .. } => None,
        }
    }
}

impl From<MigrateError> for LenientError {
    fn from(e: MigrateError) -> Self {
        Self::Read(e)
    }
}

/// Reads a policy document leniently. See [the module docs](self).
///
/// # Errors
///
/// Returns [`LenientError`] if the document cannot be read without
/// risking a relaxed decision.
pub fn read_json(input: &str) -> Result<Lenient, LenientError> {
    let UniqueValue(value) =
        serde_json::from_str(input).map_err(|e| LenientError::Read(MigrateError::Json(e)))?;
    let from = migrate::schema_version(&value)?;
    let mut value = migrate::migrate(value)?;
    let mut ignored = Vec::new();
    set_aside(&mut value, &mut ignored)?;
    let document = PolicyDocument::deserialize(value).map_err(MigrateError::Json)?;
    Ok(Lenient {
        document,
        from,
        ignored,
    })
}

/// Sets aside the unreadable governance fields and the unreadable rules
/// that never let an object run. Leaves everything else for the strict
/// reader.
fn set_aside(document: &mut Value, ignored: &mut Vec<Ignored>) -> Result<(), LenientError> {
    if let Some(policy) = document.get_mut("policy") {
        clean::<Metadata>(policy, "metadata", "/policy", ignored);
        clean::<GovernanceSettings>(policy, "governance", "/policy", ignored);
    }
    let Some(Value::Array(sets)) = document.get_mut("rule_sets") else {
        return Ok(());
    };
    for (s, set) in sets.iter_mut().enumerate() {
        let base = format!("/rule_sets/{s}");
        clean::<Metadata>(set, "metadata", &base, ignored);
        let Some(Value::Array(rules)) = set.get_mut("rules") else {
            continue;
        };
        let mut kept = Vec::with_capacity(rules.len());
        for (r, mut rule) in core::mem::take(rules).into_iter().enumerate() {
            let pointer = format!("{base}/rules/{r}");
            clean::<Metadata>(&mut rule, "metadata", &pointer, ignored);
            let Err(e) = crate::model::Rule::deserialize(&rule) else {
                kept.push(rule);
                continue;
            };
            let action = action_kind(&rule);
            match action {
                Some(
                    kind @ (ActionKind::Audit
                    | ActionKind::Defer
                    | ActionKind::TrustSource
                    | ActionKind::Ignore),
                ) => ignored.push(Ignored {
                    pointer,
                    kind: IgnoredKind::Rule(kind),
                    value: rule,
                    reason: e.to_string(),
                }),
                _ => {
                    return Err(LenientError::UnreadableRule {
                        pointer,
                        action,
                        reason: e.to_string(),
                    });
                }
            }
        }
        *rules = kept;
    }
    Ok(())
}

/// The kind of a rule's action, if its `type` is one this reader knows.
fn action_kind(rule: &Value) -> Option<ActionKind> {
    let name = rule.get("action")?.get("type")?.as_str()?;
    ActionKind::ALL.into_iter().find(|k| k.as_str() == name)
}

/// Sets aside each field of `parent[key]` that `T` cannot read on its own.
/// Every field of `T` must be optional. A value that is not an object is
/// left for the strict reader.
fn clean<T: for<'de> Deserialize<'de>>(
    parent: &mut Value,
    key: &str,
    base: &str,
    ignored: &mut Vec<Ignored>,
) {
    let Some(Value::Object(fields)) = parent.get_mut(key) else {
        return;
    };
    let mut kept = Map::new();
    for (name, value) in core::mem::take(fields) {
        let mut one = Map::new();
        one.insert(name, value);
        let one = Value::Object(one);
        let result = T::deserialize(&one).map(drop);
        let Value::Object(one) = one else {
            continue;
        };
        for (name, value) in one {
            match &result {
                Ok(()) => {
                    kept.insert(name, value);
                }
                Err(e) => ignored.push(Ignored {
                    pointer: format!("{base}/{key}/{}", pointer_token(&name)),
                    kind: IgnoredKind::GovernanceField,
                    value,
                    reason: e.to_string(),
                }),
            }
        }
    }
    *fields = kept;
}

/// Escapes one JSON Pointer reference token (RFC 6901 section 3).
fn pointer_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests;
