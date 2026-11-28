//! Agent-server messages (#223, #62): enrolment, check-in and policy fetch.
//!
//! ADR 0015 picks gRPC as the primary transport with an HTTPS + JSON
//! fallback that carries the same messages "encoded as JSON". This module
//! defines those messages, with serde JSON as the encoding, and the paths
//! they travel on over HTTP/1.1 or HTTP/2. The gRPC service definition
//! (`AgentService` in `.proto` form) and its generated code are still owed
//! to #62; when they land they carry these same message shapes, so the JSON
//! form here stays the fallback encoding.
//!
//! Every request and response type rejects unknown fields and bounds every
//! string and list, because the server parses requests from the network
//! and the agent parses responses from it. Binary values (DER, envelopes,
//! signatures) are standard base64 with padding.
//!
//! # Enrolment
//!
//! ```text
//! agent                                              server
//!   | POST /v1/enrol  (TLS, server pinned, no client certificate)
//!   |   EnrolRequest { payload, signature }   ------>  checks the code, the
//!   |     payload = JSON EnrolPayload                   source, the rate,
//!   |     signature = device key over                   and the proof of
//!   |       "palisade-enrol-v1\0" ‖ payload             possession
//!   |   <------ EnrolResponse { device cert chain, device ID, tenant,
//!   |                           root key, signed trust set, check-in URL }
//!   | then every request over mTLS with the device certificate
//! ```
//!
//! The payload is signed as the exact bytes sent, so there is no canonical
//! JSON to agree on: the server verifies the signature over the bytes it
//! received, then parses them. The payload carries a fresh nonce and its
//! creation time, so a captured request cannot be replayed once the server
//! has seen its nonce or after [`ENROL_MAX_AGE`].
//!
//! # The CA pin
//!
//! The agent is installed with one pin: the SHA-256 of the root CA's
//! `SubjectPublicKeyInfo` (`PALISADE_CA_PIN=sha256/<hex>`). The server's TLS
//! chain ends in that root, so the agent authenticates the server against
//! the pin before it sends the registration code; there is no trust on
//! first use. The same root key signs the trust sets the agent accepts
//! afterwards, whose server pins then take over for TLS.
//!
//! The enrolment endpoint is on the server's admin listener, which asks for
//! no client certificate. The agent listener stays mTLS only, and the reply
//! names its URL in `checkin_url`.
//!
//! # Check-in
//!
//! `POST /v1/checkin` over mTLS. The device is identified by its
//! certificate only (ADR 0016: the scope comes from the authenticated
//! principal, never from the body). The reply names the desired policy
//! version and trust version, the server time for skew detection, and the
//! next interval. When the agent is behind, it fetches the signed bundle
//! envelope with `GET /v1/policy` and the signed trust set with
//! `GET /v1/trust`, and checks both itself: neither is trusted because of
//! the transport (ADR 0015).

pub mod code;
pub mod http;
pub mod proxy;

#[cfg(test)]
mod tests;

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::events::{
    BoundedVec, DnsName, HostId, IpAddress, Name, Sha256Hex, TenantId, Text, Timestamp, Uuid7,
};

/// The enrolment endpoint (POST, TLS without a client certificate).
pub const PATH_ENROL: &str = "/v1/enrol";
/// The check-in endpoint (POST, mTLS).
pub const PATH_CHECKIN: &str = "/v1/checkin";
/// The policy endpoint (GET, mTLS): the device's current signed bundle
/// envelope, as `application/octet-stream`.
pub const PATH_POLICY: &str = "/v1/policy";
/// The trust-set endpoint (GET, mTLS): the current signed trust set, as
/// `application/octet-stream`.
pub const PATH_TRUST: &str = "/v1/trust";

/// The longest an enrolment payload may have been created before the server
/// receives it, in seconds. Also how far in the future it may be dated.
pub const ENROL_MAX_AGE: i64 = 5 * 60;
/// The largest enrolment request body the server reads, in bytes.
pub const MAX_ENROL_BODY: usize = 16 * 1024;
/// The largest check-in request or response body, in bytes.
pub const MAX_CHECKIN_BODY: usize = 64 * 1024;
/// The largest enrolment response body the agent reads, in bytes: a short
/// chain plus a full trust set.
pub const MAX_ENROL_RESPONSE: usize = 256 * 1024;
/// The default check-in interval, in seconds (#62).
pub const DEFAULT_CHECKIN_INTERVAL_S: u32 = 60;
/// The shortest check-in interval, in seconds (#62).
pub const MIN_CHECKIN_INTERVAL_S: u32 = 10;
/// The longest check-in interval, in seconds (#62).
pub const MAX_CHECKIN_INTERVAL_S: u32 = 86_400;

/// Most certificates in a chain the server returns.
pub const MAX_CHAIN: usize = 4;
/// Largest DER certificate accepted, in bytes.
pub const MAX_CERT_DER: usize = 8 * 1024;
/// Most MAC or IP addresses reported.
pub const MAX_ADDRESSES: usize = 32;

/// Bytes carried as standard base64 with padding, at most `MAX` bytes once
/// decoded.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Base64<const MAX: usize>(Vec<u8>);

impl<const MAX: usize> Base64<MAX> {
    /// Wraps bytes.
    ///
    /// # Errors
    ///
    /// [`WireError::TooLarge`] above `MAX` bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, WireError> {
        if bytes.len() > MAX {
            return Err(WireError::TooLarge);
        }
        Ok(Self(bytes))
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The bytes, owned.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl<const MAX: usize> fmt::Debug for Base64<MAX> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Base64({} bytes)", self.0.len())
    }
}

impl<const MAX: usize> Serialize for Base64<MAX> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use base64::Engine as _;
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(&self.0))
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for Base64<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use base64::Engine as _;
        use serde::de::Error as _;
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        // Four characters per three bytes: refuse oversized text before
        // decoding any of it.
        if text.len() > MAX.div_ceil(3).saturating_mul(4) {
            return Err(D::Error::custom(format!(
                "base64 of at most {MAX} bytes expected"
            )));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(text.as_bytes())
            .map_err(|_| D::Error::custom("standard base64 with padding expected"))?;
        Self::new(bytes).map_err(|_| D::Error::custom(format!("at most {MAX} bytes expected")))
    }
}

/// How the device key is protected (#223 `key_protection`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyProtection {
    /// A non-exportable key in the TPM-backed key storage provider (#220).
    Hardware,
    /// A software key, protected at rest by the OS (machine-scope DPAPI on
    /// Windows), or a development key.
    Software,
}

/// What a device reports about itself at enrolment (#223). Every field but
/// the hostname, OS and agent version is optional.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceFacts {
    /// The computer name.
    pub hostname: Text<255>,
    /// The fully qualified domain name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fqdn: Option<DnsName>,
    /// The OS product and version, such as `Windows 11 Pro 24H2`.
    pub os: Name,
    /// The OS build number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_build: Option<Text<64>>,
    /// The CPU architecture, such as `x86_64` or `aarch64`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<Text<32>>,
    /// The SMBIOS system UUID, used for clone detection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smbios_uuid: Option<Text<64>>,
    /// The system serial number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<Text<128>>,
    /// MAC addresses, as `aa:bb:cc:dd:ee:ff`.
    #[serde(default, skip_serializing_if = "BoundedVec::is_empty")]
    pub macs: BoundedVec<Text<17>, MAX_ADDRESSES>,
    /// The AD domain or workgroup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<Text<255>>,
    /// The agent's version.
    pub agent_version: Text<64>,
}

/// The signed part of an enrolment request. It travels as the exact JSON
/// bytes the device key signed ([`EnrolRequest::payload`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolPayload {
    /// The registration code, as typed or as installed ([`code`]).
    pub code: Text<64>,
    /// The device key's DER `SubjectPublicKeyInfo`. The certificate the
    /// server issues certifies exactly this key.
    pub public_key: Base64<{ crate::pki::key::MAX_SPKI_LEN }>,
    /// How the key is protected.
    pub key_protection: KeyProtection,
    /// A fresh random value, so each request is unique.
    pub nonce: Base64<32>,
    /// When the device made this request, by its own clock.
    pub created_at: Timestamp,
    /// What the device reports about itself.
    pub facts: DeviceFacts,
}

/// `POST /v1/enrol`: the enrolment request (#223).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolRequest {
    /// The JSON of an [`EnrolPayload`], exactly as signed.
    pub payload: Base64<8192>,
    /// The device key's proof of possession: its `r ‖ s` ECDSA P-384
    /// signature over `palisade-enrol-v1\0` followed by `payload`.
    pub signature: Base64<96>,
}

impl EnrolRequest {
    /// Builds a request: encodes `payload` as JSON and signs those bytes
    /// with `key`.
    ///
    /// # Errors
    ///
    /// [`WireError::TooLarge`] if the payload is too long, and
    /// [`WireError::Sign`] if signing fails.
    pub fn sign(
        payload: &EnrolPayload,
        key: &crate::pki::leaf_key::LeafKey,
    ) -> Result<Self, WireError> {
        let bytes = serde_json::to_vec(payload).map_err(|_| WireError::Encode)?;
        let signature = key.sign_enrolment(&bytes).map_err(WireError::Sign)?;
        Ok(Self {
            payload: Base64::new(bytes)?,
            signature: Base64::new(signature)?,
        })
    }

    /// Checks the proof of possession, then parses the payload. The
    /// signature is checked over the bytes received, before they are
    /// parsed.
    ///
    /// # Errors
    ///
    /// [`WireError::Malformed`] if the payload is not an [`EnrolPayload`] or
    /// its key is not a P-384 key in the accepted encoding, and
    /// [`WireError::BadProof`] if the signature does not verify.
    pub fn open(&self) -> Result<(EnrolPayload, crate::pki::PublicKey), WireError> {
        // The key has to come out of the payload before the signature can
        // be checked, so the payload is parsed first, but nothing in it is
        // acted on until the signature over the same bytes verifies.
        let payload: EnrolPayload =
            serde_json::from_slice(self.payload.as_bytes()).map_err(|_| WireError::Malformed)?;
        let key = crate::pki::PublicKey::from_spki_der(payload.public_key.as_bytes())
            .map_err(|_| WireError::Malformed)?;
        crate::pki::leaf_key::verify_enrolment(
            &key,
            self.payload.as_bytes(),
            self.signature.as_bytes(),
        )
        .map_err(|_| WireError::BadProof)?;
        Ok((payload, key))
    }
}

/// The reply to a successful enrolment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolResponse {
    /// The ID the server assigned to this device: the certificate's common
    /// name.
    pub device_id: HostId,
    /// The tenant the code enrolled it into.
    pub tenant_id: TenantId,
    /// The group the code enrolled it into.
    pub group_id: Uuid7,
    /// The device certificate first, then the issuing CA, DER.
    pub chain: BoundedVec<Base64<MAX_CERT_DER>, MAX_CHAIN>,
    /// The root CA's DER `SubjectPublicKeyInfo`. The agent checks that its
    /// SHA-256 is the CA pin it was installed with, then pins it as the key
    /// that signs trust sets ([`crate::pki::TrustAnchor`]). A key whose hash
    /// does not match is refused, so the server cannot choose the root.
    pub root_key: Base64<{ crate::pki::key::MAX_SPKI_LEN }>,
    /// The current signed trust set ([`crate::pki::SignedTrustSet`]).
    pub trust_set: Base64<{ crate::pki::trust_set::MAX_ENVELOPE_LEN }>,
    /// Where to check in, if not the URL enrolment used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkin_url: Option<Text<2048>>,
}

/// A health summary sent with each check-in (#67 refines it).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthSummary {
    /// Every subsystem is healthy.
    Healthy,
    /// Something is degraded.
    Degraded,
    /// Something critical has failed.
    Unhealthy,
}

/// `POST /v1/checkin`: the agent's periodic report (#62).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckIn {
    /// The agent's version.
    pub agent_version: Text<64>,
    /// The OS build.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_build: Option<Text<64>>,
    /// Seconds since the agent started.
    pub uptime_s: u64,
    /// The running policy's version, if a bundle is loaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<u64>,
    /// The running bundle's SHA-256 (#225), if a bundle is loaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_hash: Option<Sha256Hex>,
    /// The trust version the agent holds, 0 before its first trust set.
    pub trust_version: u64,
    /// The health summary.
    pub health: HealthSummary,
    /// The device's IP addresses.
    #[serde(default, skip_serializing_if = "BoundedVec::is_empty")]
    pub ips: BoundedVec<IpAddress, MAX_ADDRESSES>,
}

/// The reply to a check-in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckInResponse {
    /// The server's time, for clock-skew detection (#62: a skew over five
    /// minutes raises a health alert).
    pub server_time: Timestamp,
    /// The policy version the device should run. `None` while no bundle is
    /// published for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<u64>,
    /// The SHA-256 of that bundle, so the agent can tell a re-signed bundle
    /// from the one it runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_hash: Option<Sha256Hex>,
    /// The current trust version.
    pub trust_version: u64,
    /// Seconds until the next check-in, clamped by the agent to
    /// [`MIN_CHECKIN_INTERVAL_S`]..=[`MAX_CHECKIN_INTERVAL_S`].
    pub next_checkin_s: u32,
}

impl CheckInResponse {
    /// [`Self::next_checkin_s`] within the allowed range.
    #[must_use]
    pub fn interval_s(&self) -> u32 {
        self.next_checkin_s
            .clamp(MIN_CHECKIN_INTERVAL_S, MAX_CHECKIN_INTERVAL_S)
    }
}

/// Why the server refused a request, in the problem document's `code`
/// member. The agent acts on these; it never relies on the free text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The code is unknown, revoked, expired or used up
    /// (`enrol.rejected.code`). The agent stops retrying until it is given
    /// a new code.
    CodeRejected,
    /// The source address is outside the register restrictions
    /// (`enrol.rejected.source`).
    SourceRejected,
    /// Too many requests (`enrol.rejected.ratelimit`). Retry after the
    /// `Retry-After` delay.
    RateLimited,
    /// The policy requires a hardware key (`enrol.rejected.hardware_key`).
    HardwareKeyRequired,
    /// The request is malformed, its proof of possession does not verify,
    /// it was replayed, or it is too old.
    BadRequest,
    /// The device certificate is unknown, revoked or does not match the
    /// device record. The agent must re-enrol.
    DeviceRejected,
    /// Nothing is published for this device yet.
    NotFound,
}

/// Errors building or opening a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireError {
    /// A value is longer than its bound.
    TooLarge,
    /// A message could not be encoded.
    Encode,
    /// A message is not valid.
    Malformed,
    /// The proof of possession does not verify.
    BadProof,
    /// The device key could not sign.
    Sign(crate::pki::SignerError),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("a value is longer than its bound"),
            Self::Encode => f.write_str("the message could not be encoded"),
            Self::Malformed => f.write_str("the message is malformed"),
            Self::BadProof => f.write_str("the proof of possession does not verify"),
            Self::Sign(e) => write!(f, "the device key could not sign: {e}"),
        }
    }
}

impl std::error::Error for WireError {}
