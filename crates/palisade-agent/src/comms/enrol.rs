//! Enrolment (#223): from a registration code and a CA pin to a stored
//! device identity.
//!
//! 1. Generate a device key ([`LeafKey`]).
//! 2. Connect to the server with TLS, authenticating it by the installed CA
//!    pin only (no client certificate yet), and post the signed request.
//! 3. Check the reply before trusting any of it: the certificate it issued
//!    must certify this device's key, the root key must hash to the
//!    installed pin, and the trust set must verify under that root.
//! 4. Seal and store the identity.
//!
//! A refusal the agent cannot fix by waiting (a rejected code, a source
//! outside the restrictions, a hardware key required) is
//! [`EnrolError::Refused`]: the agent stops and waits for an administrator.
//! A rate limit or a network failure is [`EnrolError::Retry`].

#![forbid(unsafe_code)]

use std::fmt;
use std::sync::Arc;

use palisade_fileid::authenticode::CertSummary;
use palisade_proto::comms::{
    self, Base64, DeviceFacts, EnrolPayload, EnrolRequest, EnrolResponse, ErrorCode, KeyProtection,
};
use palisade_proto::events::{Sha256Hex, Text, Timestamp};
use palisade_proto::pki::leaf_key::{LeafKey, Pkcs8};
use palisade_proto::pki::{PublicKey, SkewTolerance, TrustAnchor, spki_sha256};

use super::identity::Identity;
use super::tls;
use super::transport::{Client, Endpoint, Proxy, TransportError};

/// What enrolment needs.
#[derive(Clone)]
pub struct EnrolConfig {
    /// The server's enrolment URL (`PALISADE_SERVER`).
    pub server: Endpoint,
    /// The registration code (`PALISADE_REGCODE`). A secret until used.
    pub code: String,
    /// The installed CA pin (`PALISADE_CA_PIN=sha256/<hex>`).
    pub ca_pin: Sha256Hex,
    /// An explicit proxy, if any.
    pub proxy: Option<Proxy>,
}

impl fmt::Debug for EnrolConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrolConfig")
            .field("server", &self.server)
            .field("code", &"[REDACTED]")
            .field("ca_pin", &self.ca_pin)
            .field("proxy", &self.proxy)
            .finish()
    }
}

/// Parses a CA pin: `sha256/` and 64 lowercase hex digits.
///
/// # Errors
///
/// A message if it is not in that form.
pub fn parse_pin(text: &str) -> Result<Sha256Hex, String> {
    text.strip_prefix("sha256/")
        .and_then(|hex| hex.parse().ok())
        .ok_or_else(|| "a CA pin is sha256/ followed by 64 lowercase hex digits".to_owned())
}

/// Why enrolment did not complete.
#[derive(Debug)]
pub enum EnrolError {
    /// The server refused for a reason waiting will not fix.
    Refused(ErrorCode),
    /// Try again later: a rate limit (with the server's delay, if any), a
    /// network failure or a server error.
    Retry {
        /// Why.
        reason: String,
        /// The server's `Retry-After`, in seconds.
        after: Option<u32>,
    },
    /// The server's chain did not end in the pinned CA.
    PinMismatch,
    /// The reply failed a check: possible tampering or a misconfigured
    /// server. Nothing from it was stored.
    BadReply(String),
    /// A local failure: key generation or the request could not be built.
    Local(String),
}

impl fmt::Display for EnrolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(code) => write!(f, "the server refused the enrolment ({code:?})"),
            Self::Retry { reason, .. } => write!(f, "enrolment will be retried: {reason}"),
            Self::PinMismatch => f.write_str(
                "the server's certificate chain does not end in the pinned CA (transport.pin_mismatch)",
            ),
            Self::BadReply(e) => write!(f, "the enrolment reply failed a check: {e}"),
            Self::Local(e) => write!(f, "enrolment failed locally: {e}"),
        }
    }
}

impl std::error::Error for EnrolError {}

impl From<TransportError> for EnrolError {
    fn from(e: TransportError) -> Self {
        match e {
            TransportError::PinMismatch => Self::PinMismatch,
            other => Self::Retry {
                reason: other.to_string(),
                after: None,
            },
        }
    }
}

/// A random 32-byte nonce.
fn nonce() -> Result<Vec<u8>, EnrolError> {
    // The device key generator draws from the same OS source; a fresh key's
    // public point would also do, but a dedicated draw is clearer. `rustls`
    // exposes the provider's secure random source.
    let mut n = vec![0u8; 32];
    tls::provider()
        .secure_random
        .fill(&mut n)
        .map_err(|_| EnrolError::Local("the secure random source failed".to_owned()))?;
    Ok(n)
}

/// Enrols the device. Returns the identity and the device key's PKCS#8
/// document, for the caller to seal.
///
/// # Errors
///
/// [`EnrolError`].
pub async fn enrol(
    config: &EnrolConfig,
    facts: DeviceFacts,
    now: Timestamp,
) -> Result<(Identity, Pkcs8), EnrolError> {
    let (key, pkcs8) = LeafKey::generate().map_err(|e| EnrolError::Local(e.to_string()))?;
    let payload = EnrolPayload {
        code: Text::new(config.code.clone())
            .map_err(|_| EnrolError::Refused(ErrorCode::CodeRejected))?,
        public_key: Base64::new(key.public_key().spki_der().to_vec())
            .map_err(|e| EnrolError::Local(e.to_string()))?,
        key_protection: KeyProtection::Software,
        nonce: Base64::new(nonce()?).map_err(|e| EnrolError::Local(e.to_string()))?,
        created_at: now,
        facts,
    };
    let request =
        EnrolRequest::sign(&payload, &key).map_err(|e| EnrolError::Local(e.to_string()))?;
    let body = serde_json::to_vec(&request).map_err(|e| EnrolError::Local(e.to_string()))?;
    let tls = tls::client_config(vec![config.ca_pin], None).map_err(EnrolError::Local)?;
    let client = Client::new(config.server.clone(), tls, config.proxy.clone());
    let response = client
        .request(
            "POST",
            comms::PATH_ENROL,
            Some(&body),
            comms::MAX_ENROL_RESPONSE,
        )
        .await?;
    if response.status != 200 {
        return Err(refusal(
            response.status,
            &response.body,
            response.retry_after,
        ));
    }
    let reply: EnrolResponse = serde_json::from_slice(&response.body)
        .map_err(|_| EnrolError::BadReply("not an enrolment response".to_owned()))?;
    let identity = check_reply(reply, key, &config.ca_pin, &config.server, now)?;
    Ok((identity, pkcs8))
}

/// Maps a refusal's status and problem `code` to an [`EnrolError`].
pub(super) fn refusal(status: u16, body: &[u8], retry_after: Option<u32>) -> EnrolError {
    let code = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("code").cloned())
        .and_then(|c| serde_json::from_value::<ErrorCode>(c).ok());
    match code {
        Some(
            c @ (ErrorCode::CodeRejected
            | ErrorCode::SourceRejected
            | ErrorCode::HardwareKeyRequired),
        ) => EnrolError::Refused(c),
        Some(ErrorCode::BadRequest) if status == 400 => EnrolError::Refused(ErrorCode::BadRequest),
        _ => EnrolError::Retry {
            reason: format!("the server answered {status}"),
            after: retry_after,
        },
    }
}

/// Checks everything in the reply against what the device knows.
pub(super) fn check_reply(
    reply: EnrolResponse,
    key: LeafKey,
    pin: &Sha256Hex,
    server: &Endpoint,
    now: Timestamp,
) -> Result<Identity, EnrolError> {
    let bad = |s: &str| EnrolError::BadReply(s.to_owned());
    if spki_sha256(reply.root_key.as_bytes()) != *pin {
        return Err(bad("the root key does not match the installed CA pin"));
    }
    let root = PublicKey::from_spki_der(reply.root_key.as_bytes())
        .map_err(|_| bad("the root key is not a P-384 key"))?;
    let mut anchor = TrustAnchor::new(root, SkewTolerance::DEFAULT)
        .map_err(|_| bad("the root key is not a P-384 key"))?;
    anchor
        .accept(reply.trust_set.as_bytes(), now)
        .map_err(|e| EnrolError::BadReply(format!("the trust set does not verify: {e}")))?;
    let leaf = reply
        .chain
        .iter()
        .next()
        .ok_or_else(|| bad("the chain is empty"))?;
    let summary = CertSummary::from_der(leaf.as_bytes())
        .map_err(|_| bad("the device certificate does not parse"))?;
    let key_hash = spki_sha256(key.public_key().spki_der()).to_string();
    if summary.spki_sha256 != key_hash {
        return Err(bad("the certificate does not certify this device's key"));
    }
    if summary.subject.common_name() != Some(reply.device_id.0.to_string().as_str()) {
        return Err(bad("the certificate is not for the device ID in the reply"));
    }
    let checkin_url = match &reply.checkin_url {
        Some(u) => {
            Endpoint::parse(u.as_str()).map_err(EnrolError::BadReply)?;
            u.to_string()
        }
        None => server.to_string(),
    };
    Ok(Identity {
        device: reply.device_id,
        tenant: reply.tenant_id,
        group: reply.group_id,
        chain: reply.chain.iter().map(|c| c.as_bytes().to_vec()).collect(),
        root_key: reply.root_key.into_bytes(),
        trust_set: reply.trust_set.into_bytes(),
        checkin_url,
        key: Arc::new(key),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_parse_strictly() {
        let hex = "ab".repeat(32);
        assert!(parse_pin(&format!("sha256/{hex}")).is_ok());
        assert!(parse_pin(&hex).is_err());
        assert!(parse_pin(&format!("sha256/{}", "AB".repeat(32))).is_err());
        assert!(parse_pin("sha256/abc").is_err());
    }

    #[test]
    fn refusals_are_told_apart_from_retries() {
        let body = |c: &str| format!(r#"{{"status":403,"code":"{c}"}}"#).into_bytes();
        assert!(matches!(
            refusal(403, &body("code_rejected"), None),
            EnrolError::Refused(ErrorCode::CodeRejected)
        ));
        assert!(matches!(
            refusal(403, &body("source_rejected"), None),
            EnrolError::Refused(ErrorCode::SourceRejected)
        ));
        assert!(matches!(
            refusal(403, &body("hardware_key_required"), None),
            EnrolError::Refused(ErrorCode::HardwareKeyRequired)
        ));
        assert!(matches!(
            refusal(400, &body("bad_request"), None),
            EnrolError::Refused(ErrorCode::BadRequest)
        ));
        assert!(matches!(
            refusal(429, &body("rate_limited"), Some(30)),
            EnrolError::Retry {
                after: Some(30),
                ..
            }
        ));
        assert!(matches!(
            refusal(503, b"oops", None),
            EnrolError::Retry { .. }
        ));
    }

    #[test]
    fn the_config_never_prints_the_code() {
        let c = EnrolConfig {
            server: Endpoint::parse("https://localhost:8443").unwrap(),
            code: "SECRETCODE12".to_owned(),
            ca_pin: Sha256Hex::from_bytes([0; 32]),
            proxy: None,
        };
        assert!(!format!("{c:?}").contains("SECRETCODE12"));
        for e in [
            EnrolError::Refused(ErrorCode::CodeRejected),
            EnrolError::Retry {
                reason: "x".to_owned(),
                after: None,
            },
            EnrolError::PinMismatch,
            EnrolError::BadReply("x".to_owned()),
            EnrolError::Local("x".to_owned()),
        ] {
            assert!(!e.to_string().is_empty());
        }
        assert!(matches!(
            EnrolError::from(TransportError::PinMismatch),
            EnrolError::PinMismatch
        ));
        assert!(matches!(
            EnrolError::from(TransportError::Timeout),
            EnrolError::Retry { .. }
        ));
    }
}
