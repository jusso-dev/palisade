//! Loading a bundle in one step (#43, #42).
//!
//! [`load`] turns bundle bytes into a [`LoadedPolicy`]: it decodes them
//! strictly ([`PolicyBundle::decode`]), validates the body as a policy
//! ([`PolicyBundle::validate`]), adds the agent's own `system_baseline`
//! if it has one, and builds the evaluation indexes with the bundle's
//! inlined library sets ([`BundleSets`]), so scopes and location profiles
//! read exactly the sets the server compiled in. Any failure leaves
//! nothing half-built: the caller keeps its current policy.
//!
//! The bytes must already be verified (#225). `load` does not check a
//! signature, the target or `min_agent_version`; it reads what it is
//! given, safely, and refuses anything that is not a valid bundle.

use core::fmt;

use super::compile::BundleSets;
use super::format::{BundleError, BundleLimits, Header, PolicyBundle, Sha256Digest, bundle_hash};
use crate::engine::Snapshot;
use crate::evaluate::BuildError;
use crate::scope::CompiledProfiles;
use crate::unknown::SystemBaseline;
use crate::unknown::baseline::BaselineError;
use crate::validate::{ValidatedPolicy, ValidationError};

/// Why bytes could not be loaded as a policy. The agent keeps its current
/// policy and reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadError {
    /// The bytes are not a bundle this reader reads.
    Decode(BundleError),
    /// The body is not a valid policy.
    Invalid(Vec<ValidationError>),
    /// The agent's system baseline facts do not fit in one rule.
    Baseline(BaselineError),
    /// A match tree does not compile, which validation rules out.
    Build(BuildError),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "the bundle does not decode: {e}"),
            Self::Invalid(errors) => {
                write!(
                    f,
                    "the bundle's policy is not valid ({} findings)",
                    errors.len()
                )?;
                if let Some(first) = errors.first() {
                    write!(f, ": {first}")?;
                }
                Ok(())
            }
            Self::Baseline(e) => write!(f, "the system baseline does not build: {e}"),
            Self::Build(e) => write!(f, "the bundle's policy does not compile: {e}"),
        }
    }
}

impl std::error::Error for LoadError {}

/// A bundle, decoded, validated and compiled: ready for
/// [`Engine::from_loaded`](crate::engine::Engine::from_loaded) or
/// [`Engine::install`](crate::engine::Engine::install).
#[derive(Debug)]
pub struct LoadedPolicy {
    header: Header,
    bundle_hash: Sha256Digest,
    profiles: CompiledProfiles,
    snapshot: Snapshot,
}

impl LoadedPolicy {
    /// The bundle's header.
    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// SHA-256 of the bytes loaded ([`bundle_hash`]), for events (#16).
    #[must_use]
    pub const fn bundle_hash(&self) -> &Sha256Digest {
        &self.bundle_hash
    }

    /// The validated policy, with the system baseline if one was added.
    #[must_use]
    pub fn policy(&self) -> &ValidatedPolicy {
        self.snapshot.policy()
    }

    /// The policy's location profiles, compiled with the bundle's sets,
    /// for the agent's location tracker (#38).
    #[must_use]
    pub const fn profiles(&self) -> &CompiledProfiles {
        &self.profiles
    }

    /// The compiled snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    pub(crate) fn into_snapshot(self) -> Snapshot {
        self.snapshot
    }
}

/// Decodes, validates and compiles a bundle in one step. `baseline` is the
/// agent's `system_baseline` facts, if it has any
/// ([`ValidatedPolicy::with_system_baseline`]); a bundle never carries
/// the baseline itself.
///
/// # Errors
///
/// [`LoadError`] if the bytes do not decode within `limits`, the policy is
/// not valid, the baseline does not build, or a tree does not compile.
pub fn load(
    bytes: &[u8],
    limits: &BundleLimits,
    baseline: Option<&SystemBaseline>,
) -> Result<LoadedPolicy, LoadError> {
    let bundle = PolicyBundle::decode(bytes, limits).map_err(LoadError::Decode)?;
    let mut policy = bundle.validate().map_err(LoadError::Invalid)?;
    if let Some(facts) = baseline {
        policy = policy
            .with_system_baseline(facts)
            .map_err(LoadError::Baseline)?;
    }
    let sets = BundleSets::new(&bundle);
    let profiles = CompiledProfiles::compile(&policy.document().policy.location_profiles, &sets);
    // The generation is set when an engine takes the snapshot.
    let snapshot = Snapshot::with_library(policy, &sets, 0).map_err(LoadError::Build)?;
    Ok(LoadedPolicy {
        header: bundle.header,
        bundle_hash: bundle_hash(bytes),
        profiles,
        snapshot,
    })
}

#[cfg(test)]
mod tests;
