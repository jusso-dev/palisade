//! Compiling a bundle from a policy (#43).
//!
//! [`compile`] takes a [`ValidatedPolicy`], usually the flattened policy of
//! an [`EffectivePolicy`] (inheritance
//! already merged, match-tree references already expanded, scope set
//! references pinned to versions), and the library catalogue those pins
//! name. It inlines every library set a scope reads, records the sources,
//! and builds the canonical body. Nothing platform-specific is
//! precompiled: the agent builds its indexes when it loads the bundle
//! (#42).
//!
//! [`BundleSets`] is the inlined sets as a
//! [`ScopeLibrary`], so a loaded bundle
//! evaluates with exactly the sets the server compiled in.

use core::fmt;
use std::collections::BTreeMap;

use super::format::{Body, Header, InlineLibrary, PolicyBundle, SetContent, SourceRevisions};
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
    /// The policy has an `error` finding. Validated policies have none, so
    /// this is only a guard.
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

/// Compiles `source` into a bundle with `header`, within `max_bytes`.
///
/// The same inputs always give the same bytes, on every platform: the body
/// is canonical ([`Body::new`]) and the encoding deterministic.
///
/// # Errors
///
/// [`CompileError`] if a set does not resolve, or the bundle is too large.
pub fn compile(
    source: &Source<'_>,
    header: Header,
    max_bytes: usize,
) -> Result<(PolicyBundle, Vec<u8>), CompileError> {
    if let Some(e) = source
        .policy
        .warnings()
        .iter()
        .find(|w| w.severity == Severity::Error)
    {
        return Err(CompileError::Invalid(e.to_string()));
    }
    let doc = source.policy.document();
    let mut libraries = Vec::new();
    for (_, scope) in crate::scope::document_scopes(doc) {
        for (_, r, _) in crate::scope::set_refs(scope) {
            let unresolved = || CompileError::UnresolvedSet {
                id: r.id,
                pin: r.pin,
            };
            let lib = source
                .catalogue
                .resolve(&r, source.from)
                .map_err(|_| unresolved())?;
            libraries.push(InlineLibrary {
                id: lib.id,
                resolved_version: lib.version,
                content: SetContent::of(&lib.content).ok_or_else(unresolved)?,
            });
        }
    }
    let body =
        Body::new(doc.clone(), libraries, source.sources.clone()).map_err(CompileError::Encode)?;
    let bundle = PolicyBundle::new(header, body);
    let bytes = bundle.to_bytes().map_err(CompileError::Encode)?;
    if bytes.len() > max_bytes {
        return Err(CompileError::TooLarge {
            size: bytes.len(),
            limit: max_bytes,
        });
    }
    Ok((bundle, bytes))
}

/// The library sets inlined in a bundle, as a scope library. A reference
/// resolves only at the version the bundle holds: a pinned reference to
/// that version, or a `latest` reference when the bundle holds exactly one
/// version of the library. Anything else is unresolved, so a scope that
/// needs it is unknown, as with a missing set.
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
