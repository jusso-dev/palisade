//! The `policy_cache` subsystem: loads the policy at startup, then keeps
//! its health up to date.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use palisade_core::platform::Clock;
use palisade_proto::{events::Timestamp, policy_bundle::select::Load};
use tokio::sync::broadcast;

use super::{Enforcement, PolicyCache, PolicyStatus, Reverified, clamp_timestamp};
use crate::{
    control::HostEvent,
    host::ConfigSubsystem,
    subsystem::{BoxFuture, Criticality, Health, Subsystem, SubsystemContext, SubsystemError},
};

/// How often staleness is checked.
pub const STATUS_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// How often the running bundle is re-verified by default (#326, #225: 15
/// minutes). [`PolicyCacheSubsystem::with_reverify_interval`] changes it.
pub const REVERIFY_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// The `policy_cache` subsystem.
///
/// It is critical: without it nothing decides, so if it fails for good the
/// agent enters `FailSafe`. Its health is `Degraded` while it runs a
/// built-in policy (`PolicyMissing` or `PolicyEmergency`) or a stale bundle
/// (`PolicyStale`), and `Healthy` otherwise.
pub struct PolicyCacheSubsystem {
    cache: Arc<PolicyCache>,
    clock: Arc<dyn Clock + Send + Sync>,
    health: Mutex<Health>,
    reverify_every: Duration,
}

impl PolicyCacheSubsystem {
    /// The subsystem's name.
    pub const NAME: &'static str = "policy_cache";

    /// The subsystem around `cache`. `clock` should be the agent's trusted
    /// time (#220).
    pub fn new(cache: Arc<PolicyCache>, clock: Arc<dyn Clock + Send + Sync>) -> Self {
        Self {
            cache,
            clock,
            health: Mutex::new(Health::Unhealthy("not loaded yet".into())),
            reverify_every: REVERIFY_INTERVAL,
        }
    }

    /// The same subsystem, re-verifying every `every` (at least a second).
    #[must_use]
    pub fn with_reverify_interval(mut self, every: Duration) -> Self {
        self.reverify_every = every.max(Duration::from_secs(1));
        self
    }

    /// The cache, for the subsystems that decide (#59, #113).
    pub fn cache(&self) -> &Arc<PolicyCache> {
        &self.cache
    }

    fn now(&self) -> Timestamp {
        clamp_timestamp(self.clock.now_utc().0)
    }

    /// Reads the status and updates the health. Logs `policy.stale` when the
    /// policy becomes stale.
    fn refresh(&self) -> PolicyStatus {
        let status = self.cache.status(self.now());
        let next = health_of(&status);
        let mut health = self
            .health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if next != *health
            && let Some(staleness) = status.staleness
            && staleness.is_stale()
        {
            let _ = self.cache.events().emit(super::PolicyEvent {
                detail: super::Detail::Stale(staleness),
                load: status.load,
            });
        }
        *health = next;
        status
    }
}

impl std::fmt::Debug for PolicyCacheSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyCacheSubsystem")
            .field("cache", &self.cache)
            .field("health", &self.health)
            .finish_non_exhaustive()
    }
}

/// The health a status maps to.
pub fn health_of(status: &PolicyStatus) -> Health {
    match status.load {
        Load::FirstInstall => Health::Degraded("PolicyMissing: no policy received yet".into()),
        Load::Emergency => match status.enforcement {
            Enforcement::Palisade => Health::Degraded(
                "PolicyEmergency: no cached policy loads; the emergency policy enforces".into(),
            ),
            Enforcement::NativeOnly => Health::Degraded(
                "PolicyEmergencyUnenforced: no cached policy loads; the emergency policy is audited only and the installed native policy enforces".into(),
            ),
        },
        Load::Active { .. } | Load::Previous(_) => match status.staleness {
            Some(s) if s.is_stale() => Health::Degraded("PolicyStale".into()),
            _ => Health::Healthy,
        },
    }
}

impl Subsystem for PolicyCacheSubsystem {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn criticality(&self) -> Criticality {
        Criticality::Critical
    }

    fn dependencies(&self) -> &[&'static str] {
        &[ConfigSubsystem::NAME]
    }

    fn run(self: Arc<Self>, ctx: SubsystemContext) -> BoxFuture<Result<(), SubsystemError>> {
        Box::pin(async move {
            let mut events = ctx.host_events();
            let cache = Arc::clone(&self.cache);
            let now = self.now();
            let report = tokio::task::spawn_blocking(move || cache.load_startup(now))
                .await
                .map_err(|e| SubsystemError::new(format!("policy startup did not finish: {e}")))?;
            for error in &report.io_errors {
                tracing::error!(error, "policy cache I/O error");
            }
            for finding in &report.findings {
                tracing::warn!(
                    event = finding.event_type().as_str(),
                    ?finding,
                    "policy cache finding"
                );
            }
            tracing::info!(
                load = ?report.load,
                rapid_check_in = report.rapid_check_in,
                "policy loaded"
            );
            self.refresh();
            ctx.set_ready();

            let mut tick = tokio::time::interval(STATUS_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let start = tokio::time::Instant::now() + self.reverify_every;
            let mut reverify = tokio::time::interval_at(start, self.reverify_every);
            reverify.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ctx.stopped() => return Ok(()),
                    _ = tick.tick() => {
                        self.refresh();
                    }
                    _ = reverify.tick() => {
                        let cache = Arc::clone(&self.cache);
                        let now = self.now();
                        let found = tokio::task::spawn_blocking(move || cache.reverify(now))
                            .await
                            .map_err(|e| SubsystemError::new(format!("policy re-verification did not finish: {e}")))?;
                        if found != Reverified::Intact && found != Reverified::Builtin {
                            tracing::error!(?found, "policy re-verification found a change");
                        }
                        self.refresh();
                    }
                    event = events.recv() => match event {
                        Ok(HostEvent::TimeChange) | Err(broadcast::error::RecvError::Lagged(_)) => {
                            self.refresh();
                        }
                        Ok(_) => {}
                        Err(broadcast::error::RecvError::Closed) => {
                            ctx.stopped().await;
                            return Ok(());
                        }
                    },
                }
            }
        })
    }

    fn health(&self) -> Health {
        self.health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}
