//! Device enrolment and check-in (#223, #62): the server side.
//!
//! - `POST /v1/enrol` is served on the **admin** listener, which asks for no
//!   client certificate. It checks, in order: the source rate limit, the
//!   proof of possession over the bytes received, the payload's age and
//!   nonce (replay), the per-code rate limit, then the code itself (known,
//!   not revoked, not expired, uses left, source allowed, hardware key if
//!   required). Only then does it assign a device ID and issue a device
//!   certificate for the key in the request. Every refusal is logged as one
//!   of the `enrol.rejected.*` reasons and answered with a problem document
//!   carrying an [`ErrorCode`]; nothing about the code is echoed.
//! - `POST /v1/checkin`, `GET /v1/policy` and `GET /v1/trust` are served on
//!   the **agent** listener, which requires a client certificate chaining to
//!   the issuing CA. Each request's certificate must also be the current
//!   certificate of an enrolled, unrevoked device: the serial and the key
//!   hash are looked up in the store on every request, so a revocation takes
//!   effect at once (#223). The device's tenant comes from that record,
//!   never from the request (ADR 0016).
//!
//! State is behind [`EnrolStore`]; the development server uses
//! [`MemoryStore`]. The certificate authority is [`Authority`].

pub mod authority;
pub mod dev;
pub mod limit;
pub mod store;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use palisade_fileid::authenticode::CertSummary;
use palisade_proto::comms::{
    self, Base64, CheckIn, CheckInResponse, ENROL_MAX_AGE, EnrolRequest, EnrolResponse, ErrorCode,
    code,
};
use palisade_proto::events::{BoundedVec, HostId, Sha256Hex, Text, Timestamp, Uuid7};
use palisade_proto::pki::{Clock, spki_sha256};
use serde_json::json;

use crate::http::{ClientCert, Peer};
use crate::problem::Problem;

pub use authority::Authority;
pub use store::{CodeRecord, CodeRefusal, DeviceRecord, EnrolStore, IpNet, MemoryStore, Published};

use limit::Limiter;

/// Enrolments allowed per source address per minute (#223).
pub const SOURCE_LIMIT_PER_MINUTE: u32 = 10;
/// Enrolments allowed per code per hour (#223).
pub const CODE_LIMIT_PER_HOUR: u32 = 100;
/// The default device certificate lifetime, in days (#223).
pub const DEFAULT_CERT_DAYS: u16 = 30;

/// Settings for the enrolment service.
#[derive(Debug, Clone)]
pub struct EnrolSettings {
    /// Device certificate lifetime in days, 1 to 90.
    pub cert_days: u16,
    /// The check-in interval sent to agents.
    pub checkin_interval_s: u32,
    /// The agent listener's URL, sent in the enrolment reply.
    pub checkin_url: Option<String>,
}

impl Default for EnrolSettings {
    fn default() -> Self {
        Self {
            cert_days: DEFAULT_CERT_DAYS,
            checkin_interval_s: comms::DEFAULT_CHECKIN_INTERVAL_S,
            checkin_url: None,
        }
    }
}

/// Everything the handlers share.
pub struct EnrolService {
    store: Arc<dyn EnrolStore>,
    authority: Arc<Authority>,
    pepper: code::Pepper,
    clock: Arc<dyn Clock + Send + Sync>,
    settings: EnrolSettings,
    by_source: Limiter<IpAddr>,
    by_code: Limiter<Sha256Hex>,
}

impl std::fmt::Debug for EnrolService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrolService")
            .field("store", &self.store)
            .field("authority", &self.authority)
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl EnrolService {
    /// A service over `store` and `authority`.
    pub fn new(
        store: Arc<dyn EnrolStore>,
        authority: Arc<Authority>,
        pepper: code::Pepper,
        clock: Arc<dyn Clock + Send + Sync>,
        settings: EnrolSettings,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            authority,
            pepper,
            clock,
            settings,
            by_source: Limiter::new(SOURCE_LIMIT_PER_MINUTE, Duration::from_secs(60)),
            by_code: Limiter::new(CODE_LIMIT_PER_HOUR, Duration::from_secs(3600)),
        })
    }

    /// The routes for the admin listener: enrolment.
    pub fn admin_routes(self: &Arc<Self>) -> Router {
        Router::new()
            .route(comms::PATH_ENROL, post(enrol))
            .with_state(Arc::clone(self))
    }

    /// The routes for the agent listener: check-in, policy and trust set.
    pub fn agent_routes(self: &Arc<Self>) -> Router {
        Router::new()
            .route(comms::PATH_CHECKIN, post(check_in))
            .route(comms::PATH_POLICY, get(policy))
            .route(comms::PATH_TRUST, get(trust))
            .with_state(Arc::clone(self))
    }

    /// The device this request's client certificate belongs to.
    fn device(&self, cert: Option<&ClientCert>) -> Result<DeviceRecord, Refusal> {
        let cert = cert.ok_or(Refusal(StatusCode::UNAUTHORIZED, ErrorCode::DeviceRejected))?;
        let summary = CertSummary::from_der(&cert.0)
            .map_err(|_| Refusal(StatusCode::UNAUTHORIZED, ErrorCode::DeviceRejected))?;
        let serial = decode_hex(&summary.serial)
            .ok_or(Refusal(StatusCode::UNAUTHORIZED, ErrorCode::DeviceRejected))?;
        let key: Sha256Hex = summary
            .spki_sha256
            .parse()
            .map_err(|_| Refusal(StatusCode::UNAUTHORIZED, ErrorCode::DeviceRejected))?;
        let device = self
            .store
            .device_by_certificate(&serial, &key)
            .ok_or_else(|| {
                tracing::warn!(
                    event = "device.rejected",
                    "a certificate that is not a current device certificate was refused"
                );
                Refusal(StatusCode::FORBIDDEN, ErrorCode::DeviceRejected)
            })?;
        // The common name is the device ID; a mismatch means the record and
        // the certificate disagree, so refuse.
        if summary.subject.common_name() != Some(device.device.0.to_string().as_str()) {
            return Err(Refusal(StatusCode::FORBIDDEN, ErrorCode::DeviceRejected));
        }
        Ok(device)
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| s.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
        .collect()
}

/// A refusal before it becomes a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Refusal(StatusCode, ErrorCode);

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        refuse(self.0, self.1)
    }
}

/// A refusal: a problem document with a machine-readable `code`.
fn refuse(status: StatusCode, code: ErrorCode) -> Response {
    let mut p = Problem::for_status(status);
    p = p.with_extension("code", json!(code));
    p.into_response()
}

fn rate_limited(retry_after: Duration) -> Response {
    let mut res = refuse(StatusCode::TOO_MANY_REQUESTS, ErrorCode::RateLimited);
    let secs = retry_after.as_secs().max(1);
    if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
        res.headers_mut().insert(header::RETRY_AFTER, v);
    }
    res
}

fn json_response<T: serde::Serialize>(value: &T) -> Response {
    match serde_json::to_vec(value) {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn binary_response(body: &[u8]) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        body.to_vec(),
    )
        .into_response()
}

/// A fresh UUIDv7 for a device: 48 bits of milliseconds, the version, and
/// random bits.
fn new_device_id(now: Timestamp) -> Option<HostId> {
    let mut bytes = [0u8; 16];
    crate::tls::fill_random(&mut bytes).ok()?;
    let millis = u64::try_from(now.unix_micros() / 1000).ok()?;
    let ms = millis.to_be_bytes();
    bytes.get_mut(..6)?.copy_from_slice(ms.get(2..)?);
    if let Some(b) = bytes.get_mut(6) {
        *b = 0x70 | (*b & 0x0f);
    }
    if let Some(b) = bytes.get_mut(8) {
        *b = 0x80 | (*b & 0x3f);
    }
    Uuid7::from_bytes(bytes).map(HostId)
}

async fn enrol(
    State(svc): State<Arc<EnrolService>>,
    Extension(Peer(peer)): Extension<Peer>,
    body: Bytes,
) -> Response {
    let now = svc.clock.now();
    let source = peer.ip();
    if let Err(retry) = svc.by_source.check(&source, now) {
        tracing::warn!(event = "enrol.rejected.ratelimit", %source, "enrolment rate limit (source)");
        return rate_limited(retry);
    }
    if body.len() > comms::MAX_ENROL_BODY {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let Ok(request) = serde_json::from_slice::<EnrolRequest>(&body) else {
        return refuse(StatusCode::BAD_REQUEST, ErrorCode::BadRequest);
    };
    let Ok((payload, key)) = request.open() else {
        tracing::warn!(event = "enrol.rejected.code", %source, "enrolment refused: malformed request or bad proof of possession");
        return refuse(StatusCode::BAD_REQUEST, ErrorCode::BadRequest);
    };
    let age = now
        .unix_micros()
        .saturating_sub(payload.created_at.unix_micros());
    if age.abs() > ENROL_MAX_AGE * 1_000_000 {
        return refuse(StatusCode::BAD_REQUEST, ErrorCode::BadRequest);
    }
    let Some(nonce_expiry) = Timestamp::from_unix_micros(
        now.unix_micros()
            .saturating_add(2 * ENROL_MAX_AGE * 1_000_000),
    ) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if !svc
        .store
        .remember_nonce(payload.nonce.as_bytes(), now, nonce_expiry)
    {
        tracing::warn!(event = "enrol.rejected.replay", %source, "enrolment refused: replayed request");
        return refuse(StatusCode::BAD_REQUEST, ErrorCode::BadRequest);
    }
    let Ok(code) = code::normalise(payload.code.as_str()) else {
        tracing::warn!(event = "enrol.rejected.code", %source, "enrolment refused: code");
        return refuse(StatusCode::FORBIDDEN, ErrorCode::CodeRejected);
    };
    let hash = svc.pepper.hash(&code);
    if let Err(retry) = svc.by_code.check(&hash, now) {
        tracing::warn!(event = "enrol.rejected.ratelimit", %source, "enrolment rate limit (code)");
        return rate_limited(retry);
    }
    let record = match svc
        .store
        .consume_code(&hash, source, payload.key_protection, now)
    {
        Ok(r) => r,
        Err(CodeRefusal::Rejected) => {
            tracing::warn!(event = "enrol.rejected.code", %source, "enrolment refused: code");
            return refuse(StatusCode::FORBIDDEN, ErrorCode::CodeRejected);
        }
        Err(CodeRefusal::Source) => {
            tracing::warn!(event = "enrol.rejected.source", %source, "enrolment refused: source address");
            return refuse(StatusCode::FORBIDDEN, ErrorCode::SourceRejected);
        }
        Err(CodeRefusal::HardwareKey) => {
            tracing::warn!(event = "enrol.rejected.hardware_key", %source, "enrolment refused: software key");
            return refuse(StatusCode::FORBIDDEN, ErrorCode::HardwareKeyRequired);
        }
    };
    let Some(device) = new_device_id(now) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let cert =
        match svc
            .authority
            .issue_device(&key, device, record.tenant, now, svc.settings.cert_days)
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "device certificate issuance failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
    svc.store.add_device(DeviceRecord {
        device,
        tenant: record.tenant,
        group: record.group,
        key_sha256: spki_sha256(key.spki_der()),
        serial: cert.serial().to_vec(),
        key_protection: payload.key_protection,
        hostname: payload.facts.hostname.to_string(),
        enrolled_at: now,
        last_seen: None,
        revoked: false,
    });
    tracing::info!(
        event = "enrol.succeeded",
        device = %device.0,
        tenant = %record.tenant.0,
        group = %record.group,
        %source,
        "device enrolled"
    );
    let mut chain = vec![cert.der().to_vec()];
    chain.extend(svc.authority.chain());
    let response = (|| {
        Some(EnrolResponse {
            device_id: device,
            tenant_id: record.tenant,
            group_id: record.group,
            chain: BoundedVec::new(
                chain
                    .into_iter()
                    .map(Base64::new)
                    .collect::<Result<Vec<_>, _>>()
                    .ok()?,
            )
            .ok()?,
            root_key: Base64::new(svc.authority.root_key().spki_der().to_vec()).ok()?,
            trust_set: Base64::new(svc.authority.trust_set().to_vec()).ok()?,
            checkin_url: match &svc.settings.checkin_url {
                Some(u) => Some(Text::new(u.clone()).ok()?),
                None => None,
            },
        })
    })();
    match response {
        Some(r) => json_response(&r),
        None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn check_in(
    State(svc): State<Arc<EnrolService>>,
    cert: Option<Extension<ClientCert>>,
    body: Bytes,
) -> Response {
    let device = match svc.device(cert.as_ref().map(|e| &e.0)) {
        Ok(d) => d,
        Err(r) => return r.into_response(),
    };
    if body.len() > comms::MAX_CHECKIN_BODY {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let Ok(report) = serde_json::from_slice::<CheckIn>(&body) else {
        return refuse(StatusCode::BAD_REQUEST, ErrorCode::BadRequest);
    };
    let now = svc.clock.now();
    svc.store.touch(device.device, now);
    tracing::info!(
        event = "agent.checkin",
        device = %device.device.0,
        policy_version = report.policy_version,
        trust_version = report.trust_version,
        health = ?report.health,
        "check-in"
    );
    let published = svc.store.published(device.tenant, device.group);
    json_response(&CheckInResponse {
        server_time: now,
        policy_version: published.as_ref().map(|p| p.version),
        bundle_hash: published.as_ref().map(|p| p.bundle_hash),
        trust_version: svc.authority.trust_version(),
        next_checkin_s: svc.settings.checkin_interval_s,
    })
}

async fn policy(
    State(svc): State<Arc<EnrolService>>,
    cert: Option<Extension<ClientCert>>,
) -> Response {
    let device = match svc.device(cert.as_ref().map(|e| &e.0)) {
        Ok(d) => d,
        Err(r) => return r.into_response(),
    };
    match svc.store.published(device.tenant, device.group) {
        Some(p) => binary_response(&p.envelope),
        None => refuse(StatusCode::NOT_FOUND, ErrorCode::NotFound),
    }
}

async fn trust(
    State(svc): State<Arc<EnrolService>>,
    cert: Option<Extension<ClientCert>>,
) -> Response {
    if let Err(r) = svc.device(cert.as_ref().map(|e| &e.0)) {
        return r.into_response();
    }
    binary_response(&svc.authority.trust_set())
}
