//! Palisade's own images: allowed by hash and signer, and never blockable by
//! tenant rules (#39).
//!
//! The agent describes each image it ships as a [`SelfImage`]: the facts its
//! own file-identity parser computed for the file (#3), and the context it
//! runs in. It passes them to
//! [`Evaluator::with_self_images`](crate::evaluate::Evaluator::with_self_images).
//! An object whose SHA-256 is one of them, and which carries a trusted
//! signature from that image's publisher, is allowed (`self_allow`) right
//! after stage 1, whatever the ordinary rules, exclusions and
//! unknown-handling levels say. Both pins must hold, so a copy signed by
//! someone else, or a re-signed file with other content, is not pinned.
//!
//! The mandatory-deny tier still runs first, as ADR 0004 requires of every
//! allow. Instead, [`PolicyDocument::validate_with_self_images`] rejects
//! every deny, mandatory or not, that **could** match a pinned image
//! (`deny_matches_self`): one whose tree is anything but `NoMatch` on the
//! image's facts, in its context, with the given path variables. A tree
//! that is `Unknown` there depends on something the image's facts do not
//! settle (a device fact, a missing fact), so it might block the agent on
//! some device, and it is rejected too. The check therefore errs towards
//! rejecting a policy, never towards publishing one that could block the
//! agent.

use crate::condition::{CompiledMatch, Unparseable};
use crate::context::EvaluationContext;
use crate::facts::{ObjectFacts, PathVariables};
use crate::model::{Action, Field, ObjectType, PolicyDocument};
use crate::ops::{EvalContext, Tri, fold, normalize_hex};
use crate::validate::{ErrorCode, Severity, ValidatedPolicy, ValidationError};

/// One of Palisade's own images, pinned by hash and signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfImage {
    object_type: ObjectType,
    sha256: String,
    publisher: String,
    facts: ObjectFacts,
    context: EvaluationContext,
}

impl SelfImage {
    /// The object type of the image.
    #[must_use]
    pub const fn object_type(&self) -> ObjectType {
        self.object_type
    }

    /// An image of type `object_type`, pinned to the SHA-256 in `facts` and
    /// to `publisher`. `facts` should be everything the agent's parser
    /// computed for the file, including its path; `context` is the user,
    /// device and session the image runs in.
    ///
    /// Returns `None` unless `facts` holds a 64-digit SHA-256 and a trusted
    /// signature from `publisher`, which must not be empty.
    #[must_use]
    pub fn new(
        object_type: ObjectType,
        publisher: &str,
        mut facts: ObjectFacts,
        context: EvaluationContext,
    ) -> Option<Self> {
        let sha256 = facts
            .get(Field::HashSha256)
            .and_then(normalize_hex)
            .filter(|h| h.len() == 64)?;
        let publisher = publisher.trim();
        if publisher.is_empty() || !signed_by(&facts, publisher) {
            return None;
        }
        // The canonical forms, as validated documents hold hashes, so the
        // deny check compares like with like.
        for field in Field::ALL {
            if matches!(field.class(), crate::model::FieldClass::Hash { .. }) {
                if let Some(hex) = facts.get(field).and_then(normalize_hex) {
                    facts.set(field, hex);
                }
            }
        }
        for signer in facts.signers.iter_mut().flatten() {
            if let Some(hex) = signer
                .leaf_thumbprint_sha256
                .as_deref()
                .and_then(normalize_hex)
            {
                signer.leaf_thumbprint_sha256 = Some(hex);
            }
        }
        Some(Self {
            object_type,
            sha256,
            publisher: publisher.to_owned(),
            facts,
            context,
        })
    }

    /// The pinned SHA-256, lowercase hex.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Whether an object of type `t` with `facts` is this image: the same
    /// SHA-256 and a trusted signature from the same publisher.
    #[must_use]
    pub fn matches(&self, t: ObjectType, facts: &ObjectFacts) -> bool {
        t == self.object_type
            && facts
                .get(Field::HashSha256)
                .and_then(normalize_hex)
                .as_deref()
                == Some(self.sha256.as_str())
            && signed_by(facts, &self.publisher)
    }
}

/// Whether `facts` carry a trusted signature from `publisher`, compared as
/// criteria compare text (without case).
fn signed_by(facts: &ObjectFacts, publisher: &str) -> bool {
    let want = fold(publisher, false);
    facts.signers.as_deref().is_some_and(|signers| {
        signers.iter().any(|s| {
            s.status.is_trusted()
                && s.publisher.as_deref().map(|p| fold(p, false)) == Some(want.clone())
        })
    })
}

impl PolicyDocument {
    /// Validates the document ([`PolicyDocument::validate`]), and then, if
    /// it is valid, also rejects every deny that could match one of `images`
    /// (`deny_matches_self`). A deny could match an image when its object
    /// types include the image's type and its tree is not `NoMatch` on the
    /// image's facts, in the image's context, with `variables` (the path
    /// variables of the devices the policy is for).
    ///
    /// # Errors
    ///
    /// Returns every finding if any has `error` severity.
    pub fn validate_with_self_images(
        self,
        images: &[SelfImage],
        variables: &PathVariables,
    ) -> Result<ValidatedPolicy, Vec<ValidationError>> {
        // Validation first: it enforces the rule and regular-expression
        // limits before anything is compiled, and a rejected document needs
        // no further check.
        let validated = self.validate()?;
        if images.is_empty() {
            return Ok(validated);
        }
        let mut extra = Vec::new();
        for (i, set) in validated.document().rule_sets.iter().enumerate() {
            for (j, rule) in set.rules.iter().enumerate() {
                if !matches!(rule.action, Action::Deny(_)) {
                    continue;
                }
                // Every tree of a validated document compiles.
                let Ok(tree) = CompiledMatch::compile(&rule.match_) else {
                    continue;
                };
                for image in images {
                    if !rule.object_types.is_empty()
                        && !rule.object_types.contains(&image.object_type)
                    {
                        continue;
                    }
                    let ctx = EvalContext {
                        action: rule.action.kind(),
                        variables,
                        context: &image.context,
                    };
                    // Whatever the deny's options, only `NoMatch` is safe.
                    let result = tree
                        .eval_with(&image.facts, &ctx, Unparseable::FavourMatch)
                        .result;
                    if result != Tri::NoMatch {
                        extra.push(ValidationError {
                            code: ErrorCode::DenyMatchesSelf,
                            severity: Severity::Error,
                            path: format!("/rule_sets/{i}/rules/{j}/match"),
                            message: format!(
                                "this deny {} Palisade's own {} `{}`; the agent cannot be blocked by policy, so narrow the rule until it cannot match the agent",
                                if result == Tri::Match { "matches" } else { "could match, depending on facts it does not settle," },
                                image.object_type,
                                image.sha256
                            ),
                        });
                        break;
                    }
                }
            }
        }
        if extra.is_empty() {
            Ok(validated)
        } else {
            let mut all = validated.warnings().to_vec();
            all.extend(extra);
            Err(all)
        }
    }
}
