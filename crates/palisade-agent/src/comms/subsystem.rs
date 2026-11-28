//! The comms subsystem: enrol if needed, then check in until stopped.
//!
//! It is non-critical: a server that cannot be reached, a refused code or a
//! revoked device degrade its health, but the agent keeps enforcing its
//! cached policy (ADR 0018). It retries enrolment with backoff while the
//! failure is temporary, and stops trying (reporting unhealthy) when the
//! server refuses for a reason waiting will not fix.
//!
//! Handing the enrolled identity to the policy cache (#61) needs the
//! device's record key, which belongs to the protected store of #220; until
//! then the subsystem takes an optional cache and trust handle, so a host
//! that has built an enrolled cache passes them in.

#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use palisade_core::platform::Clock;
use palisade_proto::events::Timestamp;

use super::checkin::{self, Round};
use super::enrol::EnrolError;
use super::{CommsConfig, StartError, context, device_facts, load_or_enrol, run};
use crate::policy_cache::{PolicyCache, Protector, SharedTrust};
use crate::subsystem::{
    BoxFuture, Criticality, Health, Subsystem, SubsystemContext, SubsystemError,
};

/// Builds a fresh [`Protector`] for each attempt (the identity store owns
/// one).
pub type ProtectorFactory = Box<dyn Fn() -> std::io::Result<Box<dyn Protector>> + Send + Sync>;

/// The comms subsystem.
pub struct CommsSubsystem {
    config: CommsConfig,
    protector: ProtectorFactory,
    clock: Arc<dyn Clock + Send + Sync>,
    hostname: String,
    trust: Option<SharedTrust>,
    cache: Option<Arc<PolicyCache>>,
    health: Mutex<Health>,
}

impl std::fmt::Debug for CommsSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommsSubsystem")
            .field("config", &self.config)
            .field("health", &self.health)
            .finish_non_exhaustive()
    }
}

impl CommsSubsystem {
    /// The subsystem's name.
    pub const NAME: &'static str = "comms";

    /// A subsystem with `config`, sealing the identity with protectors from
    /// `protector`, reading trusted time from `clock`.
    pub fn new(
        config: CommsConfig,
        protector: ProtectorFactory,
        clock: Arc<dyn Clock + Send + Sync>,
        hostname: String,
    ) -> Self {
        Self {
            config,
            protector,
            clock,
            hostname,
            trust: None,
            cache: None,
            health: Mutex::new(Health::Degraded("not checked in yet".into())),
        }
    }

    /// The subsystem with this platform's protector (machine-scope DPAPI on
    /// Windows, a process-only key elsewhere) and clock.
    #[must_use]
    pub fn for_platform(config: CommsConfig) -> Self {
        #[cfg(windows)]
        let protector: ProtectorFactory = Box::new(|| Ok(crate::policy_cache::protect::platform()));
        #[cfg(not(windows))]
        let protector: ProtectorFactory = Box::new(|| {
            crate::policy_cache::MemoryProtector::new().map(|p| Box::new(p) as Box<dyn Protector>)
        });
        let hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "unknown".to_owned());
        Self::new(
            config,
            protector,
            Arc::new(crate::platform::SystemClock),
            hostname,
        )
    }

    /// Delivers trust sets into `trust` and bundles into `cache`.
    #[must_use]
    pub fn with_cache(mut self, trust: SharedTrust, cache: Arc<PolicyCache>) -> Self {
        self.trust = Some(trust);
        self.cache = Some(cache);
        self
    }

    fn now(&self) -> Timestamp {
        let micros = self.clock.now_utc().0;
        Timestamp::from_unix_micros(micros).unwrap_or(if micros < 0 {
            Timestamp::MIN
        } else {
            Timestamp::MAX
        })
    }

    fn set_health(&self, health: Health) {
        *self
            .health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = health;
    }

    async fn start(&self) -> Result<checkin::CheckInContext, StartError> {
        let facts = device_facts(&self.hostname)
            .ok_or_else(|| StartError::BadIdentity("the device facts are invalid".to_owned()))?;
        let protector = (self.protector)().map_err(StartError::Identity)?;
        let (identity, store) = load_or_enrol(&self.config, protector, facts, self.now()).await?;
        context(
            &identity,
            store,
            &self.config,
            self.trust.clone(),
            self.cache.clone(),
            self.now(),
        )
    }
}

impl Subsystem for CommsSubsystem {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn criticality(&self) -> Criticality {
        Criticality::NonCritical
    }

    fn run(self: Arc<Self>, ctx: SubsystemContext) -> BoxFuture<Result<(), SubsystemError>> {
        Box::pin(async move {
            ctx.set_ready();
            let mut failures = 0u32;
            let check_in = loop {
                match self.start().await {
                    Ok(c) => break c,
                    Err(StartError::NotEnrolled) => {
                        self.set_health(Health::Degraded("not enrolled".into()));
                        tracing::info!(
                            "not enrolled and no registration code configured; comms idle"
                        );
                        ctx.stopped().await;
                        return Ok(());
                    }
                    Err(StartError::Enrol(e @ EnrolError::Refused(_))) => {
                        self.set_health(Health::Unhealthy(e.to_string()));
                        tracing::error!(event = "enrol.refused", error = %e, "enrolment refused; waiting for an administrator");
                        ctx.stopped().await;
                        return Ok(());
                    }
                    Err(e) => {
                        self.set_health(Health::Degraded(e.to_string()));
                        tracing::warn!(error = %e, failures, "enrolment or start-up failed; retrying");
                        let wait = checkin::backoff(
                            failures,
                            checkin::DEFAULT_INTERVAL,
                            checkin::random_unit(),
                        );
                        failures = failures.saturating_add(1);
                        tokio::select! {
                            () = tokio::time::sleep(wait) => {}
                            _ = ctx.stopped() => return Ok(()),
                        }
                    }
                }
            };
            self.set_health(Health::Healthy);
            let this = Arc::clone(&self);
            let last = run(check_in, move || this.now(), async {
                ctx.stopped().await;
            })
            .await;
            if last == Round::Rejected {
                self.set_health(Health::Unhealthy(
                    "the server no longer accepts this device".into(),
                ));
                ctx.stopped().await;
            }
            Ok(())
        })
    }

    fn stop_timeout(&self) -> Duration {
        Duration::from_secs(2)
    }

    fn health(&self) -> Health {
        self.health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}
