//! The check-in loop (#62): heartbeat, backoff, and delivery of signed
//! trust sets and policy bundles.
//!
//! Each round posts a [`CheckIn`] over mTLS, then:
//!
//! - when the server's trust version is newer, fetches the signed trust set
//!   and accepts it only through [`TrustAnchor::accept`] (signed by the
//!   pinned root or a current trust key, newer, not from the future), then
//!   swaps it into the [`SharedTrust`] the policy cache verifies against
//!   and stores it;
//! - when the server names a policy version or bundle hash that differs
//!   from what runs, fetches the signed envelope and hands it to
//!   [`PolicyCache::activate`], which verifies the signature against the
//!   trust set and applies anti-rollback. The transport is never trusted
//!   for either (ADR 0015).
//!
//! The next round is the server's interval with ±20% jitter, so a fleet
//! does not synchronise. Failures back off exponentially with jitter, from
//! 1 s up to four check-in intervals (#62). A `Retry-After` from the server
//! is honoured. A device the server no longer recognises
//! (`device_rejected`) stops checking in and reports unhealthy; re-enrolment
//! needs an administrator.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use palisade_proto::comms::{
    self, CheckIn, CheckInResponse, DEFAULT_CHECKIN_INTERVAL_S, ErrorCode, HealthSummary,
};
use palisade_proto::events::{BoundedVec, Text, Timestamp};
use palisade_proto::pki::TrustAnchor;
use palisade_proto::policy_bundle::select::Load;

use super::transport::{Client, TransportError};
use crate::policy_cache::{Activated, PolicyCache, SharedTrust};

/// What one round did.
#[derive(Debug, PartialEq, Eq)]
pub enum Round {
    /// The check-in succeeded. Wait this long before the next.
    Ok {
        /// The server's interval, before jitter.
        interval: Duration,
        /// The server's time, for skew detection.
        server_time: Timestamp,
        /// Whether a new trust set was accepted.
        trust_updated: bool,
        /// Whether a new policy was activated.
        policy_updated: bool,
    },
    /// Try again after this delay.
    Retry {
        /// Why.
        reason: String,
        /// The server's `Retry-After`, if any.
        after: Option<Duration>,
    },
    /// The server no longer accepts this device: stop.
    Rejected,
}

/// Stores a newly accepted trust set envelope.
pub type TrustSink = Box<dyn Fn(&[u8]) + Send + Sync>;

/// What the loop needs from the rest of the agent.
pub struct CheckInContext {
    /// The mTLS client for the check-in endpoint.
    pub client: Client,
    /// The trust anchor: the pinned root and the current trust set.
    pub anchor: TrustAnchor,
    /// The trust set the policy cache verifies against.
    pub trust: SharedTrust,
    /// The policy cache, if the agent runs one for this identity.
    pub cache: Option<Arc<PolicyCache>>,
    /// Called with each newly accepted trust set's envelope, to store it.
    pub on_trust: TrustSink,
    /// The agent's start, for `uptime_s`.
    pub started: std::time::Instant,
}

impl std::fmt::Debug for CheckInContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckInContext")
            .field("client", &self.client)
            .field("trust_version", &self.anchor.trust_version())
            .finish_non_exhaustive()
    }
}

impl CheckInContext {
    fn report(&self) -> Option<CheckIn> {
        let (policy_version, bundle_hash) = match self.cache.as_ref().map(|c| c.current().load()) {
            Some(Load::Active { bundle, .. } | Load::Previous(bundle)) => {
                (Some(bundle.version), Some(bundle.sha256))
            }
            _ => (None, None),
        };
        Some(CheckIn {
            agent_version: Text::new(env!("CARGO_PKG_VERSION")).ok()?,
            os_build: None,
            uptime_s: self.started.elapsed().as_secs(),
            policy_version,
            bundle_hash,
            trust_version: self.anchor.trust_version(),
            health: HealthSummary::Healthy,
            ips: BoundedVec::default(),
        })
    }

    /// Runs one check-in round at trusted time `now`.
    pub async fn round(&mut self, now: Timestamp) -> Round {
        let Some(body) = self.report().and_then(|r| serde_json::to_vec(&r).ok()) else {
            return Round::Retry {
                reason: "the check-in report could not be built".to_owned(),
                after: None,
            };
        };
        let response = match self
            .client
            .request(
                "POST",
                comms::PATH_CHECKIN,
                Some(&body),
                comms::MAX_CHECKIN_BODY,
            )
            .await
        {
            Ok(r) => r,
            Err(TransportError::PinMismatch) => {
                tracing::error!(event = "transport.pin_mismatch", endpoint = %self.client.endpoint(), "the server's certificate chain does not end in a pinned CA; possible interception");
                return Round::Retry {
                    reason: TransportError::PinMismatch.to_string(),
                    after: None,
                };
            }
            Err(e) => {
                return Round::Retry {
                    reason: e.to_string(),
                    after: None,
                };
            }
        };
        if response.status != 200 {
            return refused(response.status, &response.body, response.retry_after);
        }
        let Ok(reply) = serde_json::from_slice::<CheckInResponse>(&response.body) else {
            return Round::Retry {
                reason: "the check-in reply is malformed".to_owned(),
                after: None,
            };
        };
        let trust_updated = self.sync_trust(&reply, now).await;
        let policy_updated = self.sync_policy(&reply, now).await;
        Round::Ok {
            interval: Duration::from_secs(u64::from(reply.interval_s())),
            server_time: reply.server_time,
            trust_updated,
            policy_updated,
        }
    }

    async fn sync_trust(&mut self, reply: &CheckInResponse, now: Timestamp) -> bool {
        if reply.trust_version <= self.anchor.trust_version() {
            return false;
        }
        let envelope = match self
            .client
            .request(
                "GET",
                comms::PATH_TRUST,
                None,
                palisade_proto::pki::trust_set::MAX_ENVELOPE_LEN,
            )
            .await
        {
            Ok(r) if r.status == 200 => r.body,
            Ok(r) => {
                tracing::warn!(status = r.status, "trust set fetch refused");
                return false;
            }
            Err(e) => {
                tracing::warn!(error = %e, "trust set fetch failed");
                return false;
            }
        };
        match self.anchor.accept(&envelope, now) {
            Ok(set) => {
                tracing::info!(
                    event = "trust.updated",
                    trust_version = set.trust_version(),
                    "new trust set accepted"
                );
                self.trust.store(Arc::new(set.clone()));
                (self.on_trust)(&envelope);
                true
            }
            Err(e) => {
                tracing::warn!(event = "trust.rejected", error = %e, "a trust set from the server was refused");
                false
            }
        }
    }

    async fn sync_policy(&mut self, reply: &CheckInResponse, now: Timestamp) -> bool {
        let Some(cache) = self.cache.clone() else {
            return false;
        };
        let Some(want) = reply.policy_version else {
            return false;
        };
        let current = match cache.current().load() {
            Load::Active { bundle, .. } | Load::Previous(bundle) => Some(bundle),
            _ => None,
        };
        if current.is_some_and(|b| b.version == want && Some(b.sha256) == reply.bundle_hash) {
            return false;
        }
        let envelope = match self
            .client
            .request("GET", comms::PATH_POLICY, None, MAX_POLICY_BYTES)
            .await
        {
            Ok(r) if r.status == 200 => r.body,
            Ok(r) => {
                tracing::warn!(status = r.status, "policy fetch refused");
                return false;
            }
            Err(e) => {
                tracing::warn!(error = %e, "policy fetch failed");
                return false;
            }
        };
        let result = tokio::task::spawn_blocking(move || cache.activate(&envelope, now)).await;
        match result {
            Ok(Ok(Activated::Activated(meta))) => {
                tracing::info!(policy_version = meta.version, "policy activated");
                true
            }
            Ok(Ok(Activated::AlreadyCurrent)) => false,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "a policy bundle from the server was not activated");
                false
            }
            Err(e) => {
                tracing::error!(error = %e, "policy activation panicked");
                false
            }
        }
    }
}

/// The largest policy envelope fetched, in bytes: the bundle format's own
/// limit.
pub const MAX_POLICY_BYTES: usize = 64 << 20;

fn refused(status: u16, body: &[u8], retry_after: Option<u32>) -> Round {
    let code = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("code").cloned())
        .and_then(|c| serde_json::from_value::<ErrorCode>(c).ok());
    if code == Some(ErrorCode::DeviceRejected) {
        tracing::error!(
            event = "device.rejected",
            "the server no longer accepts this device; re-enrolment is needed"
        );
        return Round::Rejected;
    }
    Round::Retry {
        reason: format!("the server answered {status}"),
        after: retry_after.map(|s| Duration::from_secs(u64::from(s))),
    }
}

/// The delay after `failures` consecutive failures: 1 s doubling, capped at
/// four check-in intervals, then jittered to between half and all of it.
#[must_use]
pub fn backoff(failures: u32, interval: Duration, jitter: f64) -> Duration {
    let cap = interval.saturating_mul(4).max(Duration::from_secs(1));
    let base = Duration::from_secs(1u64 << failures.min(20)).min(cap);
    base.mul_f64(0.5 + 0.5 * jitter.clamp(0.0, 1.0))
}

/// The interval with ±20% jitter (#62 `jitter_pct`).
#[must_use]
pub fn jittered(interval: Duration, jitter: f64) -> Duration {
    interval.mul_f64(0.8 + 0.4 * jitter.clamp(0.0, 1.0))
}

/// A uniform draw in `[0, 1)` from the OS secure random source, or 0.5 if
/// it fails.
#[must_use]
pub fn random_unit() -> f64 {
    let mut b = [0u8; 4];
    match super::tls::provider().secure_random.fill(&mut b) {
        Ok(()) => f64::from(u32::from_be_bytes(b)) / (f64::from(u32::MAX) + 1.0),
        Err(_) => 0.5,
    }
}

/// The interval before the first reply arrives.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(DEFAULT_CHECKIN_INTERVAL_S as u64);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_a_cap_with_jitter() {
        let i = Duration::from_secs(60);
        assert_eq!(backoff(0, i, 1.0), Duration::from_secs(1));
        assert_eq!(backoff(3, i, 1.0), Duration::from_secs(8));
        assert_eq!(backoff(30, i, 1.0), Duration::from_secs(240));
        assert_eq!(backoff(30, i, 0.0), Duration::from_secs(120));
        assert_eq!(backoff(0, Duration::ZERO, 1.0), Duration::from_secs(1));
    }

    #[test]
    fn jitter_spreads_twenty_percent_either_way() {
        let i = Duration::from_secs(100);
        assert_eq!(jittered(i, 0.0), Duration::from_secs(80));
        assert_eq!(jittered(i, 1.0), Duration::from_secs(120));
        assert_eq!(jittered(i, 0.5), Duration::from_secs(100));
        let r = random_unit();
        assert!((0.0..1.0).contains(&r));
    }

    #[test]
    fn a_rejected_device_stops_and_other_refusals_retry() {
        assert_eq!(
            refused(403, br#"{"code":"device_rejected"}"#, None),
            Round::Rejected
        );
        assert_eq!(
            refused(429, br#"{"code":"rate_limited"}"#, Some(9)),
            Round::Retry {
                reason: "the server answered 429".to_owned(),
                after: Some(Duration::from_secs(9))
            }
        );
        assert!(matches!(
            refused(500, b"", None),
            Round::Retry { after: None, .. }
        ));
    }
}
