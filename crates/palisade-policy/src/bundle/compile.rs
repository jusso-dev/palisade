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
use crate::hierarchy::EffectivePolicy;
use crate::library::{Catalogue, LibraryId, Pin, Visibility};
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
    /// pinned version, or is not a set a scope can read.
    UnresolvedSet {
        /// The library.
        id: LibraryId,
        /// The pin.
        pin: Pin,
    },
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
/// The same inputs always give the same bytes, on every platform: the body
/// is canonical ([`Body::new`]) and the encoding deterministic.
///
/// # Errors
///
/// [`CompileError`] if a set does not resolve, the header and the policy
/// disagree on the schema version, the bundle is over `limits`, or the
/// bundle an agent would read is not valid.
pub fn compile(
    source: &Source<'_>,
    header: Header,
    limits: &BundleLimits,
) -> Result<(PolicyBundle, Vec<u8>), CompileError> {
    if let Some(e) = source
        .policy
        .warnings()
        .iter()
        .find(|w| w.severity == Severity::Error)
    {
        return Err(CompileError::Invalid(e.to_string()));
    }
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
    Ok((bundle, bytes))
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
}

#[cfg(test)]
mod tests;
