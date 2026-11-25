//! Network location profiles and the debounced location the agent reports
//! (#38).
//!
//! A policy names locations in `location_profiles`, such as `corporate`:
//! every test of a profile must match. The agent evaluates the profiles on
//! each network change event and on every heartbeat (by default every
//! [`HEARTBEAT_SECS`] seconds) with [`CompiledProfiles::active`], and feeds
//! the result to a [`LocationTracker`]. The tracker keeps the previous
//! location until a new one has been observed unchanged for
//! [`DEBOUNCE_MS`], so a network that flaps while it connects does not
//! flip scopes back and forth. Scopes read the tracker's location as
//! [`NetworkContext::locations`](crate::context::NetworkContext::locations)
//! and test it with `location_profile`.
//!
//! Evaluating a profile is pure, like everything in this crate: the agent
//! supplies the network facts and the monotonic time.

use crate::context::{EvaluationContext, NetworkContext};
use crate::ops::Tri;

use super::compile::{CompiledScope, Env};
use super::model::LocationProfile;
use super::text::group_name;
use super::{NoLibrary, ScopeLibrary, ScopeNotes};

/// How long a new location must be stable before it replaces the previous
/// one, in milliseconds.
pub const DEBOUNCE_MS: u64 = 5_000;
/// The default interval at which the agent re-evaluates the location, in
/// seconds.
pub const HEARTBEAT_SECS: u64 = 60;

/// A policy's location profiles, ready to evaluate.
#[derive(Clone, Debug)]
pub struct CompiledProfiles {
    profiles: Vec<(String, CompiledScope)>,
}

impl CompiledProfiles {
    /// Compiles the profiles. Network sets resolve through `library`.
    #[must_use]
    pub fn compile(profiles: &[LocationProfile], library: &dyn ScopeLibrary) -> Self {
        let env = Env {
            library,
            basis: crate::model::TimeZoneBasis::Utc,
        };
        Self {
            profiles: profiles
                .iter()
                .map(|p| {
                    (
                        group_name(&p.name),
                        CompiledScope::all_of_network(&p.all, env),
                    )
                })
                .collect(),
        }
    }

    /// Compiles the profiles with no library.
    #[must_use]
    pub fn compile_without_library(profiles: &[LocationProfile]) -> Self {
        Self::compile(profiles, &NoLibrary)
    }

    /// The names of the profiles whose tests all match the network facts,
    /// folded for comparison, in the policy's order. A profile with an
    /// unknown test is not active.
    #[must_use]
    pub fn active(&self, network: &NetworkContext) -> Vec<String> {
        let ctx = EvaluationContext {
            network: network.clone(),
            ..EvaluationContext::default()
        };
        self.profiles
            .iter()
            .filter(|(_, scope)| {
                let mut notes = ScopeNotes::default();
                scope.eval(&ctx, super::Bias::Permissive, &mut notes).0 == Tri::Match
            })
            .map(|(name, _)| name.clone())
            .collect()
    }
}

/// The debounced network location of one device.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocationTracker {
    /// The location scopes see, and since when the latest observation has
    /// differed from it.
    current: Option<Vec<String>>,
    pending: Option<(Vec<String>, u64)>,
}

impl LocationTracker {
    /// A tracker with no location yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the profiles active at monotonic time `now_ms`, and returns
    /// the location scopes see. The first observation applies at once.
    /// Later, a different location applies only after it has been observed
    /// unchanged for [`DEBOUNCE_MS`]; in between, the previous one stays.
    pub fn observe(&mut self, mut active: Vec<String>, now_ms: u64) -> &[String] {
        active.sort();
        active.dedup();
        match &self.current {
            None => {
                self.current = Some(active);
                self.pending = None;
            }
            Some(current) if *current == active => self.pending = None,
            Some(_) => match &self.pending {
                Some((pending, since)) if *pending == active => {
                    if now_ms.saturating_sub(*since) >= DEBOUNCE_MS {
                        self.current = Some(active);
                        self.pending = None;
                    }
                }
                _ => self.pending = Some((active, now_ms)),
            },
        }
        self.current.as_deref().unwrap_or_default()
    }

    /// The location scopes see, or `None` before the first observation.
    #[must_use]
    pub fn current(&self) -> Option<&[String]> {
        self.current.as_deref()
    }
}
