//! Compiling a bundle from a policy (#43).
//!
//! [`compile`] takes a [`ValidatedPolicy`], usually the flattened policy of
//! an [`EffectivePolicy`] (inheritance
//! already merged, match-tree references already expanded, scope set
//! references pinned to versions), and the library catalogue those pins
//! name. It inlines every library set a scope or location profile reads,
//! pins every reference to the version inlined, records the sources, builds
//! the canonical body, and reads the result back as an agent would. Nothing
//! platform-specific is
//! precompiled: the agent builds its indexes when it loads the bundle
//! (#42).
//!
//! [`BundleSets`] is the inlined sets as a
//! [`ScopeLibrary`], so a loaded bundle
//! evaluates with exactly the sets the server compiled in.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use super::format::{
    Body, BundleLimits, Header, InlineLibrary, PolicyBundle, SetContent, SourceRevisions,
};
use super::serial;
use crate::analysis::{self, Facts, Finding, Gate, Override};
use crate::hierarchy::EffectivePolicy;
use crate::library::{Catalogue, LibraryId, Pin, Visibility};
use crate::model::Timestamp;
use crate::scope::{Schedule, ScopeLibrary, SetRef};
use crate::validate::{Severity, ValidatedPolicy};

/// What a bundle is compiled from.
#[derive(Clone, Debug)]
pub struct Source<'a> {
    /// The policy.
    pub policy: &'a ValidatedPolicy,
    /// The catalogue that the policy's scope set references resolve in.
    pub catalogue: &'a Catalogue,
    /// Whose libraries the policy may use.
    pub from: Visibility,
    /// The source policies and library versions, for the evidence record
    /// (ISM-1582). An effective policy gives its own ([`Source::effective`]).
    pub sources: SourceRevisions,
    /// What the policy assistant (#40) knows beyond the policy, for the
    /// analysis [`compile`] runs.
    pub facts: Facts,
    /// A tenant administrator's override of the analysis's `error`
    /// findings, if any. Without one, an `error` finding stops compilation.
    pub admin: Option<Override>,
}

impl<'a> Source<'a> {
    /// The source for a device's effective policy: its flattened policy,
    /// and its library versions as the sources. `None` for an unmanaged
    /// device, which has no policy and so no bundle.
    #[must_use]
    pub fn effective(
        effective: &'a EffectivePolicy,
        catalogue: &'a Catalogue,
        from: Visibility,
    ) -> Option<Self> {
        let policy = effective.policy()?;
        let p = &policy.document().policy;
        Some(Self {
            policy,
            catalogue,
            from,
            sources: SourceRevisions {
                policies: vec![(p.id, p.revision)],
                libraries: effective.libraries().iter().copied().collect(),
            },
            facts: Facts::default(),
            admin: None,
        })
    }
}

/// Why a bundle could not be compiled. The server keeps the last good
/// bundle of the target and retries (#43), so each is reported, never
/// fatal to the agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompileError {
    /// The policy has an `error` finding, the header and policy disagree on
    /// the schema version, or the bundle as an agent would read it is not
    /// readable within the agents' limits or not valid.
    Invalid(String),
    /// A scope references a library set that is not in the catalogue at a
    /// pinned version, or is not a set a scope can read; or a criterion
    /// names a hash set (#368) that is not in the catalogue at its pinned
    /// version as a SHA-256 hash set.
    UnresolvedSet {
        /// The library.
        id: LibraryId,
        /// The pin.
        pin: Pin,
    },
    /// The policy assistant (#40) found `error` findings and no
    /// administrator overrode them.
    Blocked(Vec<Finding>),
    /// The bundle does not encode.
    Encode(serial::Error),
    /// The bundle is larger than the limit.
    TooLarge {
        /// Its size, in bytes.
        size: usize,
        /// The limit.
        limit: usize,
    },
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(why) => write!(f, "the policy is not valid: {why}"),
            Self::UnresolvedSet { id, pin } => write!(
                f,
                "library set {id} at {pin} is not in the catalogue as a set a scope can read"
            ),
            Self::Blocked(findings) => {
                write!(
                    f,
                    "the policy assistant found {} error finding(s); fix them or have a tenant administrator override them with a reason",
                    findings.len()
                )?;
                if let Some(first) = findings.first() {
                    write!(f, ": {}: {}", first.code.as_str(), first.message)?;
                }
                Ok(())
            }
            Self::Encode(e) => write!(f, "the bundle does not encode: {e}"),
            Self::TooLarge { size, limit } => write!(
                f,
                "the bundle is {size} bytes, over the limit of {limit}: split it into a group bundle and a device bundle, or replace hash rules with signer rules"
            ),
        }
    }
}

impl std::error::Error for CompileError {}

/// Compiles `source` into a bundle with `header`.
///
/// Every library set a scope or a location profile reads is inlined, at
/// the version its reference resolves to, and each reference is rewritten
/// to pin that version: a bundle never says `latest`, so it means the same
/// on every agent whatever else it holds.
///
/// The bundle is then read back as an agent reads it: decoded within
/// `limits` (the agents' size and item limits) and validated. A bundle an
/// agent would refuse fails here instead, so the server keeps its last good
/// bundle. This also catches a policy that writing text in NFC makes
/// invalid (two tags that differ only in normal form, or a name that grows
/// past its limit in NFC).
///
/// Before anything is built, the policy assistant's static analysis
/// (#40) runs on the policy, as of the header's `generated_at`. An `error`
/// finding stops compilation ([`CompileError::Blocked`]) unless
/// `source.admin` overrides it with a reason; the override and the
/// findings it covers are returned in [`Compiled::gate`] for the caller to
/// record.
///
/// The same inputs always give the same bytes, on every platform: the body
/// is canonical ([`Body::new`]) and the encoding deterministic.
///
/// # Errors
///
/// [`CompileError`] if the analysis has `error` findings that are not
/// overridden, a set does not resolve, the header and the policy disagree
/// on the schema version, the bundle is over `limits`, or the bundle an
/// agent would read is not valid.
pub fn compile(
    source: &Source<'_>,
    header: Header,
    limits: &BundleLimits,
) -> Result<Compiled, CompileError> {
    if let Some(e) = source
        .policy
        .warnings()
        .iter()
        .find(|w| w.severity == Severity::Error)
    {
        return Err(CompileError::Invalid(e.to_string()));
    }
    let gate = analyse(source, &header)?;
    let mut doc = source.policy.document().clone();
    if doc
        .rule_sets
        .iter()
        .any(crate::unknown::baseline::is_system_baseline)
    {
        return Err(CompileError::Invalid(
            "the policy holds the managed `system_baseline`; the agent adds it from its own facts after it loads the bundle (`ValidatedPolicy::with_system_baseline`), so compile the policy without it".to_owned(),
        ));
    }
    if doc.schema_version != header.schema_version {
        return Err(CompileError::Invalid(format!(
            "the header says schema {} and the policy {}",
            header.schema_version, doc.schema_version
        )));
    }
    let mut libraries = Vec::new();
    // Each distinct set version is copied into the bundle once, however
    // many references name it: a large set referenced from many scopes
    // must not be cloned per reference before `Body::new` deduplicates.
    let mut inlined: BTreeSet<(LibraryId, u32)> = BTreeSet::new();
    let mut failed = None;
    crate::scope::for_each_document_set_ref(&mut doc, |r| {
        let resolved = source
            .catalogue
            .resolve(r, source.from)
            .ok()
            .and_then(|lib| {
                if inlined.contains(&(lib.id, lib.version)) {
                    return Some((lib, None));
                }
                Some((lib, Some(SetContent::of(&lib.content)?)))
            });
        match resolved {
            Some((lib, content)) => {
                r.pin = Pin::Version(lib.version);
                if let Some(content) = content {
                    inlined.insert((lib.id, lib.version));
                    libraries.push(InlineLibrary {
                        id: lib.id,
                        resolved_version: lib.version,
                        content,
                    });
                }
            }
            None => {
                failed.get_or_insert(CompileError::UnresolvedSet {
                    id: r.id,
                    pin: r.pin,
                });
            }
        }
    });
    if let Some(e) = failed {
        return Err(e);
    }
    // Every hash set a criterion names (#368), at its pinned version.
    // Validation already refused an unpinned one.
    for r in criterion_sets(&doc) {
        let Pin::Version(v) = r.pin else {
            return Err(CompileError::UnresolvedSet {
                id: r.id,
                pin: r.pin,
            });
        };
        if inlined.contains(&(r.id, v)) {
            continue;
        }
        let lib = source
            .catalogue
            .resolve(&r, source.from)
            .ok()
            .filter(|l| l.version == v);
        let Some((lib, content)) = lib.and_then(|l| Some((l, SetContent::of(&l.content)?))) else {
            return Err(CompileError::UnresolvedSet {
                id: r.id,
                pin: r.pin,
            });
        };
        if !matches!(content, SetContent::HashSet { .. }) {
            return Err(CompileError::UnresolvedSet {
                id: r.id,
                pin: r.pin,
            });
        }
        inlined.insert((lib.id, lib.version));
        libraries.push(InlineLibrary {
            id: lib.id,
            resolved_version: lib.version,
            content,
        });
    }
    // The evidence record names every set version the bundle carries.
    let mut sources = source.sources.clone();
    sources
        .libraries
        .extend(libraries.iter().map(|l| (l.id, l.resolved_version)));
    let body = Body::new(doc, libraries, sources).map_err(CompileError::Encode)?;
    let bundle = PolicyBundle::new(header, body);
    let bytes = bundle.to_bytes().map_err(CompileError::Encode)?;
    if bytes.len() > limits.max_bytes {
        return Err(CompileError::TooLarge {
            size: bytes.len(),
            limit: limits.max_bytes,
        });
    }
    let read = PolicyBundle::decode(&bytes, limits)
        .map_err(|e| CompileError::Invalid(format!("an agent could not read the bundle: {e}")))?;
    if let Err(errors) = read.validate() {
        let first = errors.first().map_or_else(String::new, ToString::to_string);
        return Err(CompileError::Invalid(format!(
            "the bundle an agent reads is not valid ({} findings): {first}",
            errors.len()
        )));
    }
    Ok(Compiled {
        bundle,
        bytes,
        gate,
    })
}

/// Every library hash set a criterion of `doc` names (#368), each once.
fn criterion_sets(doc: &crate::model::PolicyDocument) -> BTreeSet<crate::library::LibraryRef> {
    let mut out = BTreeSet::new();
    for rule in doc.rule_sets.iter().flat_map(|s| &s.rules) {
        let mut stack = vec![&rule.match_];
        while let Some(node) = stack.pop() {
            if let crate::model::Match::Criterion(c) = node
                && let Some(r) = c.set
            {
                out.insert(r);
            }
            stack.extend(node.children());
        }
    }
    out
}

/// A compiled bundle.
#[derive(Clone, Debug)]
pub struct Compiled {
    /// The bundle.
    pub bundle: PolicyBundle,
    /// Its canonical bytes.
    pub bytes: Vec<u8>,
    /// The outcome of the policy assistant's gate: [`Gate::Pass`], or
    /// [`Gate::Overridden`] with who overrode which `error` findings and
    /// why, for the audit record. Never [`Gate::Blocked`].
    pub gate: Gate,
}

/// Runs the policy assistant (#40) on the source policy as of the header's
/// `generated_at`, and applies the publish gate.
fn analyse(source: &Source<'_>, header: &Header) -> Result<Gate, CompileError> {
    // `generated_at` is in microseconds, the assistant's clock in seconds.
    // A time it cannot represent fails rather than skipping the
    // time-dependent checks.
    let now = Timestamp::checked(header.generated_at.div_euclid(1_000_000)).ok_or_else(|| {
        CompileError::Invalid(format!(
            "the header's generated_at ({}) is not a time the policy assistant can check against",
            header.generated_at
        ))
    })?;
    let findings = analysis::analyse(source.policy.document(), &source.facts, now);
    match analysis::publish_gate(&findings, source.admin.as_ref()) {
        Gate::Blocked(errors) => Err(CompileError::Blocked(errors)),
        gate => Ok(gate),
    }
}

/// The library sets inlined in a bundle, as a scope library. [`compile`]
/// pins every reference, so a reference resolves only at a version the
/// bundle holds; a `latest` reference, which a compiled bundle never has,
/// resolves only when the bundle holds exactly one version. Anything else
/// is unresolved, so a scope that needs it is unknown, as with a missing
/// set.
#[derive(Clone, Debug, Default)]
pub struct BundleSets {
    sets: BTreeMap<LibraryId, Vec<(u32, SetContent)>>,
}

impl BundleSets {
    /// The sets of `bundle`.
    #[must_use]
    pub fn new(bundle: &PolicyBundle) -> Self {
        let mut sets: BTreeMap<LibraryId, Vec<(u32, SetContent)>> = BTreeMap::new();
        for l in bundle.body.libraries() {
            sets.entry(l.id)
                .or_default()
                .push((l.resolved_version, l.content.clone()));
        }
        Self { sets }
    }

    fn get(&self, r: &SetRef) -> Option<&SetContent> {
        let versions = self.sets.get(&r.id)?;
        match (r.pin, versions.as_slice()) {
            (Pin::Version(v), _) => versions.iter().find(|(n, _)| *n == v).map(|(_, c)| c),
            (Pin::Latest, [(_, c)]) => Some(c),
            (Pin::Latest, _) => None,
        }
    }
}

impl ScopeLibrary for BundleSets {
    fn principal_set(&self, set: &SetRef) -> Option<Vec<String>> {
        match self.get(set)? {
            SetContent::PrincipalSet(p) => Some(p.clone()),
            _ => None,
        }
    }

    fn network_set(&self, set: &SetRef) -> Option<Vec<String>> {
        match self.get(set)? {
            SetContent::NetworkSet(e) => Some(e.clone()),
            _ => None,
        }
    }

    fn schedule_set(&self, set: &SetRef) -> Option<Schedule> {
        match self.get(set)? {
            // A validated set holds exactly one schedule, as JSON.
            SetContent::ScheduleSet(e) if e.len() == 1 => serde_json::from_str(&e[0]).ok(),
            _ => None,
        }
    }

    fn hash_set(
        &self,
        set: &SetRef,
        field: crate::model::Field,
    ) -> Option<crate::hashset::Digests> {
        // Only the exact version a criterion pins (#368).
        if set.pin == Pin::Latest {
            return None;
        }
        match self.get(set)? {
            SetContent::HashSet { field: f, digests } if *f == field => Some(digests.clone()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
