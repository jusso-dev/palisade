//! Server communication (#223 enrolment, #62 check-in).
//!
//! - [`tls`]: the TLS client. The server is authenticated by pinned root
//!   keys, never the OS store, and the device key signs the client side.
//! - [`transport`]: one HTTPS request per connection, direct or through an
//!   HTTP `CONNECT` proxy, with deadlines and bounded responses.
//! - [`enrol`]: from a registration code and CA pin to a device identity,
//!   checking every part of the reply against the pin and the device key.
//! - [`identity`]: the sealed identity file.
//! - [`checkin`]: the check-in loop, with jitter and backoff, which
//!   delivers signed trust sets and policy bundles into the policy cache.
//!
//! The messages are `palisade_proto::comms`, in the JSON encoding of ADR
//! 0015's fallback. The gRPC transport, push, relays, commands and the
//! fallback triggers are still owed to #62.
//!
//! [`run`] drives it all: load the identity (or enrol if a code is
//! configured), then check in until stopped. [`subsystem::CommsSubsystem`] is
//! the subsystem.

#![forbid(unsafe_code)]

pub mod checkin;
pub mod enrol;
pub mod identity;
pub mod subsystem;
pub mod tls;
pub mod transport;

#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use palisade_proto::comms::DeviceFacts;
use palisade_proto::events::{Name, Text, Timestamp};
use palisade_proto::pki::{PublicKey, SkewTolerance, TrustAnchor, TrustSet, spki_sha256};

use crate::policy_cache::{PolicyCache, Protector, SharedTrust};

use checkin::{CheckInContext, Round};
use enrol::{EnrolConfig, EnrolError};
use identity::{Identity, IdentityStore};
use transport::{Client, Endpoint, Proxy};

/// The install-time inputs (#223), read from the environment until the
/// installer writes them into the agent configuration (#57):
/// `PALISADE_SERVER`, `PALISADE_REGCODE`, `PALISADE_CA_PIN`, and optionally
/// `PALISADE_PROXY`, `NO_PROXY` and `PALISADE_DATA_DIR`.
///
/// Returns `Ok(None)` when `PALISADE_SERVER` is not set: comms is off.
/// Without `PALISADE_DATA_DIR` the identity goes to
/// `%ProgramData%\Palisade\data` on Windows, and to a fresh directory under
/// the system temp directory elsewhere, where nothing outlives the process
/// (development builds enrol on every start).
///
/// # Errors
///
/// A message for a value that is set but invalid. Nothing falls back to a
/// default when a value is wrong.
pub fn config_from_env(
    var: impl Fn(&str) -> Option<String>,
) -> Result<Option<CommsConfig>, String> {
    let Some(server) = var("PALISADE_SERVER") else {
        return Ok(None);
    };
    let server = Endpoint::parse(&server)?;
    let pin = var("PALISADE_CA_PIN")
        .ok_or_else(|| "PALISADE_CA_PIN is required with PALISADE_SERVER".to_owned())?;
    let ca_pin = enrol::parse_pin(&pin)?;
    let proxy = var("PALISADE_PROXY")
        .map(|p| Proxy::parse(&p))
        .transpose()?;
    let no_proxy = var("NO_PROXY")
        .or_else(|| var("no_proxy"))
        .map(|v| v.split(',').map(str::to_owned).collect())
        .unwrap_or_default();
    let data_dir = match var("PALISADE_DATA_DIR") {
        Some(d) => PathBuf::from(d),
        None if cfg!(windows) => {
            crate::config::install_path(var("ProgramData").as_deref().map(std::ffi::OsStr::new))
                .map_err(|e| e.to_string())?
                .parent()
                .map(|p| p.join("data"))
                .ok_or_else(|| "no data directory".to_owned())?
        }
        None => std::env::temp_dir().join(format!("palisade-agent-{}", std::process::id())),
    };
    let enrol = var("PALISADE_REGCODE").map(|code| EnrolConfig {
        server: server.clone(),
        code,
        ca_pin,
        proxy: proxy.clone(),
    });
    Ok(Some(CommsConfig {
        data_dir,
        enrol,
        proxy,
        no_proxy,
    }))
}

/// What the comms subsystem is configured with.
#[derive(Debug, Clone)]
pub struct CommsConfig {
    /// Where the identity file lives.
    pub data_dir: PathBuf,
    /// Enrolment settings, used only while the device is not enrolled.
    pub enrol: Option<EnrolConfig>,
    /// An explicit proxy for check-in, if any.
    pub proxy: Option<Proxy>,
    /// Hosts that bypass the proxy.
    pub no_proxy: Vec<String>,
}

/// Why [`load_or_enrol`] or [`context`] could not produce a check-in context.
#[derive(Debug)]
pub enum StartError {
    /// Not enrolled, and no enrolment settings.
    NotEnrolled,
    /// Enrolment did not complete.
    Enrol(EnrolError),
    /// The identity file could not be read or written.
    Identity(std::io::Error),
    /// The stored identity is inconsistent.
    BadIdentity(String),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotEnrolled => {
                f.write_str("the device is not enrolled and no registration code is configured")
            }
            Self::Enrol(e) => e.fmt(f),
            Self::Identity(e) => write!(f, "the device identity file: {e}"),
            Self::BadIdentity(e) => write!(f, "the device identity is inconsistent: {e}"),
        }
    }
}

impl std::error::Error for StartError {}

/// The facts the agent reports at enrolment. Development builds report
/// what they can; the platform layer fills in the rest (#60).
#[must_use]
pub fn device_facts(hostname: &str) -> Option<DeviceFacts> {
    Some(DeviceFacts {
        hostname: Text::new(hostname).ok()?,
        fqdn: None,
        os: Name::new(std::env::consts::OS).ok()?,
        os_build: None,
        arch: Text::new(std::env::consts::ARCH).ok(),
        smbios_uuid: None,
        serial: None,
        macs: palisade_proto::events::BoundedVec::default(),
        domain: None,
        agent_version: Text::new(env!("CARGO_PKG_VERSION")).ok()?,
    })
}

/// Loads the identity, or enrols if there is none and enrolment is
/// configured. Returns the identity.
///
/// # Errors
///
/// [`StartError`].
pub async fn load_or_enrol(
    config: &CommsConfig,
    protector: Box<dyn Protector>,
    facts: DeviceFacts,
    now: Timestamp,
) -> Result<(Identity, IdentityStore), StartError> {
    let store = IdentityStore::new(&config.data_dir, protector);
    if let Some(identity) = store.load().map_err(StartError::Identity)? {
        return Ok((identity, store));
    }
    let enrol = config.enrol.as_ref().ok_or(StartError::NotEnrolled)?;
    let (identity, pkcs8) = enrol::enrol(enrol, facts, now)
        .await
        .map_err(StartError::Enrol)?;
    store
        .save(&identity, &pkcs8)
        .map_err(StartError::Identity)?;
    tracing::info!(
        event = "enrol.succeeded",
        device = %identity.device.0,
        tenant = %identity.tenant.0,
        "the device enrolled"
    );
    Ok((identity, store))
}

/// The trust anchor and current trust set from a stored identity.
///
/// # Errors
///
/// [`StartError::BadIdentity`] if the stored root or trust set does not
/// verify, which only tampering or a bug can cause.
pub fn anchor_of(
    identity: &Identity,
    now: Timestamp,
) -> Result<(TrustAnchor, TrustSet), StartError> {
    let root = PublicKey::from_spki_der(&identity.root_key)
        .map_err(|e| StartError::BadIdentity(e.to_string()))?;
    let mut anchor = TrustAnchor::new(root, SkewTolerance::DEFAULT)
        .map_err(|e| StartError::BadIdentity(e.to_string()))?;
    // The stored set was accepted at enrolment or a later check-in; it is
    // checked again here, at trusted time, rather than taken on trust.
    let set = anchor
        .accept(&identity.trust_set, now)
        .map_err(|e| StartError::BadIdentity(format!("the stored trust set: {e}")))?
        .clone();
    Ok((anchor, set))
}

/// The check-in context for `identity`: an mTLS client pinned to the trust
/// set's server pins (and the root), the trust anchor, and the cache.
///
/// # Errors
///
/// [`StartError::BadIdentity`].
pub fn context(
    identity: &Identity,
    store: IdentityStore,
    config: &CommsConfig,
    trust: Option<SharedTrust>,
    cache: Option<Arc<PolicyCache>>,
    now: Timestamp,
) -> Result<CheckInContext, StartError> {
    let (anchor, set) = anchor_of(identity, now)?;
    let mut pins: Vec<_> = set.server_pins().copied().collect();
    pins.push(spki_sha256(&identity.root_key));
    let tls = tls::client_config(pins, Some((identity.chain.clone(), identity.key.clone())))
        .map_err(StartError::BadIdentity)?;
    let endpoint = Endpoint::parse(&identity.checkin_url).map_err(StartError::BadIdentity)?;
    let proxy = config
        .proxy
        .clone()
        .filter(|_| !transport::bypasses(&config.no_proxy, &endpoint.host));
    let trust = match trust {
        Some(t) => {
            t.store(Arc::new(set));
            t
        }
        None => Arc::new(ArcSwap::from_pointee(set)),
    };
    let store = Arc::new(store);
    Ok(CheckInContext {
        client: Client::new(endpoint, tls, proxy),
        anchor,
        trust,
        cache,
        on_trust: Box::new(move |envelope| {
            if let Err(e) = store.update_trust_set(envelope) {
                tracing::warn!(error = %e, "the new trust set could not be stored");
            }
        }),
        started: std::time::Instant::now(),
    })
}

/// Checks in until `stop` resolves, sleeping between rounds. `now` gives
/// trusted time.
pub async fn run(
    mut ctx: CheckInContext,
    now: impl Fn() -> Timestamp,
    stop: impl std::future::Future<Output = ()>,
) -> Round {
    tokio::pin!(stop);
    let mut interval = checkin::DEFAULT_INTERVAL;
    let mut failures = 0u32;
    loop {
        let round = ctx.round(now()).await;
        let wait = match &round {
            Round::Ok { interval: i, .. } => {
                failures = 0;
                interval = *i;
                checkin::jittered(interval, checkin::random_unit())
            }
            Round::Retry { reason, after } => {
                tracing::warn!(reason, failures, "check-in failed");
                let backoff = checkin::backoff(failures, interval, checkin::random_unit());
                failures = failures.saturating_add(1);
                after.map_or(backoff, |a| a.max(backoff).min(interval.saturating_mul(4)))
            }
            Round::Rejected => return round,
        };
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = &mut stop => return round,
        }
    }
}
