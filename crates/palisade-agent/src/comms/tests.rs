//! End-to-end tests of enrolment and check-in against a stand-in server.
//!
//! The agent may not depend on `palisade-server` (ADR 0003), so these tests
//! run a small TLS server here, built from the same pieces the real one
//! uses: `rustls` with the issued server certificate, client certificates
//! required on the check-in listener, and the internal CA from
//! `palisade_proto::pki::issue`. `palisade-server`'s own tests cover its
//! routes; these cover the agent's half of the protocol.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use palisade_proto::comms::{Base64, CheckInResponse, EnrolRequest, EnrolResponse, ErrorCode};
use palisade_proto::events::{BoundedVec, DnsName, HostId, Sha256Hex, TenantId, Timestamp, Uuid7};
use palisade_proto::pki::issue::{CaCertificate, LeafCertificate};
use palisade_proto::pki::leaf_key::LeafKey;
use palisade_proto::pki::{
    KeyPurpose, KeyStatus, Kid, SignatureAlgorithm, SignedTrustSet, Signer as _, SoftwareSigner,
    TrustSet, TrustedKey, Validity, spki_sha256,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::enrol::{self, EnrolConfig, EnrolError};
use super::transport::{Endpoint, Proxy};
use super::*;
use crate::policy_cache::MemoryProtector;

const DAY: i64 = 86_400 * 1_000_000;

fn now() -> Timestamp {
    use palisade_proto::pki::Clock as _;
    palisade_proto::pki::SystemClock.now()
}

fn window(from: i64, to: i64) -> Validity {
    let n = now().unix_micros();
    Validity::new(
        Timestamp::from_unix_micros(n + from * DAY).unwrap(),
        Timestamp::from_unix_micros(n + to * DAY).unwrap(),
    )
    .unwrap()
}

fn uuid(s: &str) -> Uuid7 {
    Uuid7::from_str(s).unwrap()
}

/// The stand-in server's PKI and state.
struct Pki {
    signer: SoftwareSigner,
    root: CaCertificate,
    issuing: CaCertificate,
    policy_kid: Kid,
    server_chain: Vec<Vec<u8>>,
    server_key: Vec<u8>,
    trust_sets: Vec<Vec<u8>>,
}

impl Pki {
    fn new() -> Self {
        let p384 = SignatureAlgorithm::EcdsaP384Sha384;
        let mut signer = SoftwareSigner::new();
        let root_kid = signer.generate(KeyPurpose::RootCa, p384).unwrap();
        let issuing_kid = signer.generate(KeyPurpose::IssuingCa, p384).unwrap();
        let policy_kid = signer.generate(KeyPurpose::PolicySigning, p384).unwrap();
        let root =
            CaCertificate::self_signed_root(&signer, &root_kid, "Test Root", window(-1, 3650))
                .unwrap();
        let issuing = CaCertificate::issuing_ca(
            &signer,
            &root,
            &signer.public_key(&issuing_kid).unwrap(),
            "Test Issuing",
            window(-1, 1000),
        )
        .unwrap();
        let (server_key, server_pkcs8) = LeafKey::generate().unwrap();
        let server = LeafCertificate::server(
            &signer,
            &issuing,
            server_key.public_key(),
            &[DnsName::from_str("localhost").unwrap()],
            window(-1, 300),
        )
        .unwrap();
        let mut pki = Self {
            server_chain: vec![
                server.der().to_vec(),
                issuing.der().to_vec(),
                root.der().to_vec(),
            ],
            server_key: server_pkcs8.expose().to_vec(),
            signer,
            root,
            issuing,
            policy_kid,
            trust_sets: Vec::new(),
        };
        pki.trust_sets.push(pki.trust_set(1));
        pki.trust_sets.push(pki.trust_set(2));
        pki
    }

    fn trust_set(&self, version: u64) -> Vec<u8> {
        let p384 = SignatureAlgorithm::EcdsaP384Sha384;
        let mut set = TrustSet::new(version, now(), &[p384]).unwrap();
        set.add_trust_key(
            TrustedKey::new(
                self.root.public_key().clone(),
                KeyPurpose::RootCa,
                p384,
                KeyStatus::Active,
                self.root.validity(),
            )
            .unwrap(),
        )
        .unwrap();
        set.add_server_pin(self.root.public_key().spki_sha256())
            .unwrap();
        set.add_policy_key(
            TrustedKey::new(
                self.signer.public_key(&self.policy_kid).unwrap(),
                KeyPurpose::PolicySigning,
                p384,
                KeyStatus::Active,
                window(-1, 300),
            )
            .unwrap(),
        )
        .unwrap();
        SignedTrustSet::sign(&set, &self.signer, &[self.root.kid()])
            .unwrap()
            .encode()
    }

    fn pin(&self) -> Sha256Hex {
        self.root.public_key().spki_sha256()
    }
}

#[derive(Default)]
struct State {
    /// Device ID → (serial, key hash, revoked).
    devices: BTreeMap<HostId, (Vec<u8>, Sha256Hex, bool)>,
    /// The trust version the server offers.
    trust_version: u64,
    /// The policy envelope and version published for the device.
    policy: Option<(u64, Sha256Hex, Vec<u8>)>,
    /// Enrolments seen.
    enrolments: u32,
}

struct Server {
    pki: Pki,
    state: Mutex<State>,
    code: &'static str,
    checkin_port: Mutex<u16>,
}

const TENANT: &str = "019a0000-0000-7000-8000-0000000000aa";
const GROUP: &str = "019a0000-0000-7000-8000-0000000000bb";
const DEVICE: &str = "019a0000-0000-7000-8000-000000000001";

fn tls_config(pki: &Pki, client_auth: bool) -> Arc<ServerConfig> {
    let provider = Arc::new(tls::provider());
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap();
    let builder = if client_auth {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(pki.issuing.der().to_vec()))
            .unwrap();
        builder.with_client_cert_verifier(
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .unwrap(),
        )
    } else {
        builder.with_no_client_auth()
    };
    Arc::new(
        builder
            .with_single_cert(
                pki.server_chain
                    .iter()
                    .map(|c| CertificateDer::from(c.clone()))
                    .collect(),
                PrivatePkcs8KeyDer::from(pki.server_key.clone()).into(),
            )
            .unwrap(),
    )
}

/// Serves HTTP/1.1 requests on `listener` with `handle`, one per
/// connection.
async fn serve(listener: TcpListener, acceptor: TlsAcceptor, server: Arc<Server>) {
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };
        let acceptor = acceptor.clone();
        let server = server.clone();
        tokio::spawn(async move {
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                return;
            };
            let cert = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .map(|c| c.as_ref().to_vec());
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let (head_end, len) = loop {
                let n = tls.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..end]).to_lowercase();
                    let len = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .map_or(0, |v| v.trim().parse::<usize>().unwrap());
                    break (end + 4, len);
                }
            };
            while buf.len() < head_end + len {
                let n = tls.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            let line =
                String::from_utf8_lossy(&buf[..buf.iter().position(|&b| b == b'\r').unwrap()])
                    .into_owned();
            let body = &buf[head_end..head_end + len];
            let (status, ctype, out) = server.handle(&line, body, cert.as_deref());
            let reply = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                out.len()
            );
            let _ = tls.write_all(reply.as_bytes()).await;
            let _ = tls.write_all(&out).await;
            let _ = tls.shutdown().await;
        });
    }
}

fn problem(status: u16, code: ErrorCode) -> (u16, &'static str, Vec<u8>) {
    (
        status,
        "application/problem+json",
        serde_json::to_vec(&serde_json::json!({ "status": status, "code": code })).unwrap(),
    )
}

impl Server {
    fn handle(&self, line: &str, body: &[u8], cert: Option<&[u8]>) -> (u16, &'static str, Vec<u8>) {
        match line {
            l if l.starts_with("POST /v1/enrol ") => self.enrol(body),
            l if l.starts_with("POST /v1/checkin ") => {
                if !self.known(cert) {
                    return problem(403, ErrorCode::DeviceRejected);
                }
                let s = self.state.lock().unwrap();
                let reply = CheckInResponse {
                    server_time: now(),
                    policy_version: s.policy.as_ref().map(|p| p.0),
                    bundle_hash: s.policy.as_ref().map(|p| p.1),
                    trust_version: s.trust_version,
                    next_checkin_s: 10,
                };
                (200, "application/json", serde_json::to_vec(&reply).unwrap())
            }
            l if l.starts_with("GET /v1/trust ") => {
                if !self.known(cert) {
                    return problem(403, ErrorCode::DeviceRejected);
                }
                let v = self.state.lock().unwrap().trust_version;
                let index = usize::try_from(v).unwrap() - 1;
                (
                    200,
                    "application/octet-stream",
                    self.pki.trust_sets[index].clone(),
                )
            }
            l if l.starts_with("GET /v1/policy ") => {
                if !self.known(cert) {
                    return problem(403, ErrorCode::DeviceRejected);
                }
                match &self.state.lock().unwrap().policy {
                    Some(p) => (200, "application/octet-stream", p.2.clone()),
                    None => problem(404, ErrorCode::NotFound),
                }
            }
            _ => problem(404, ErrorCode::NotFound),
        }
    }

    fn known(&self, cert: Option<&[u8]>) -> bool {
        let Some(cert) = cert else { return false };
        let Ok(summary) = palisade_fileid::authenticode::CertSummary::from_der(cert) else {
            return false;
        };
        let s = self.state.lock().unwrap();
        s.devices.values().any(|(serial, key, revoked)| {
            !revoked
                && summary.spki_sha256 == key.to_string()
                && summary.serial
                    == serial
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
        })
    }

    fn enrol(&self, body: &[u8]) -> (u16, &'static str, Vec<u8>) {
        let Ok(request) = serde_json::from_slice::<EnrolRequest>(body) else {
            return problem(400, ErrorCode::BadRequest);
        };
        let Ok((payload, key)) = request.open() else {
            return problem(400, ErrorCode::BadRequest);
        };
        if payload.code.as_str() != self.code {
            return problem(403, ErrorCode::CodeRejected);
        }
        let device = HostId(uuid(DEVICE));
        let tenant = TenantId(uuid(TENANT));
        let cert = LeafCertificate::device(
            &self.pki.signer,
            &self.pki.issuing,
            &key,
            device,
            tenant,
            window(0, 30),
        )
        .unwrap();
        let mut s = self.state.lock().unwrap();
        s.enrolments += 1;
        s.trust_version = 1;
        s.devices.insert(
            device,
            (cert.serial().to_vec(), spki_sha256(key.spki_der()), false),
        );
        drop(s);
        let reply = EnrolResponse {
            device_id: device,
            tenant_id: tenant,
            group_id: uuid(GROUP),
            chain: BoundedVec::new(vec![
                Base64::new(cert.der().to_vec()).unwrap(),
                Base64::new(self.pki.issuing.der().to_vec()).unwrap(),
            ])
            .unwrap(),
            root_key: Base64::new(self.pki.root.public_key().spki_der().to_vec()).unwrap(),
            trust_set: Base64::new(self.pki.trust_sets[0].clone()).unwrap(),
            checkin_url: Some(palisade_proto::events::Text::new(self.checkin_url()).unwrap()),
        };
        (200, "application/json", serde_json::to_vec(&reply).unwrap())
    }

    fn checkin_url(&self) -> String {
        format!("https://localhost:{}", *self.checkin_port.lock().unwrap())
    }
}

struct Env {
    server: Arc<Server>,
    enrol_addr: SocketAddr,
}

async fn start(code: &'static str) -> Env {
    let pki = Pki::new();
    let enrol_tls = TlsAcceptor::from(tls_config(&pki, false));
    let agent_tls = TlsAcceptor::from(tls_config(&pki, true));
    let server = Arc::new(Server {
        pki,
        state: Mutex::new(State::default()),
        code,
        checkin_port: Mutex::new(0),
    });
    let enrol_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let agent_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let enrol_addr = enrol_listener.local_addr().unwrap();
    *server.checkin_port.lock().unwrap() = agent_listener.local_addr().unwrap().port();
    tokio::spawn(serve(enrol_listener, enrol_tls, server.clone()));
    tokio::spawn(serve(agent_listener, agent_tls, server.clone()));
    Env { server, enrol_addr }
}

fn enrol_config(env: &Env, code: &str, pin: Sha256Hex) -> EnrolConfig {
    EnrolConfig {
        server: Endpoint::parse(&format!("https://localhost:{}", env.enrol_addr.port())).unwrap(),
        code: code.to_owned(),
        ca_pin: pin,
        proxy: None,
    }
}

fn data_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("palisade-comms-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// A signed policy bundle for the enrolled device, version `version`.
fn policy_envelope(pki: &Pki, version: u64) -> (Sha256Hex, Vec<u8>) {
    use palisade_policy::bundle::{
        Body, Header, PolicyBundle, SourceRevisions, Target, TargetScope,
    };
    use palisade_policy::test_util::{PolicyBuilder, RuleBuilder, RuleSetBuilder, hash};
    let doc = PolicyBuilder::new()
        .rule_set(RuleSetBuilder::allowlist(1).rule(RuleBuilder::allow(1, hash('a'))))
        .build();
    let header = Header::new(
        Target {
            tenant: uuid(TENANT),
            scope: TargetScope::Device(uuid(DEVICE)),
        },
        version,
        now().unix_micros(),
    );
    let bundle = PolicyBundle::new(
        header,
        Body::new(doc, Vec::new(), SourceRevisions::default()).unwrap(),
    )
    .to_bytes()
    .unwrap();
    let envelope = palisade_proto::policy_bundle::envelope::Envelope::sign_bundle(
        &bundle,
        &pki.signer,
        &[pki.policy_kid],
    )
    .unwrap()
    .encode();
    (
        palisade_proto::policy_bundle::content_hash(&bundle),
        envelope,
    )
}

/// A started policy cache for the enrolled device that verifies against
/// `trust`.
fn cache(dir: &std::path::Path, trust: SharedTrust) -> Arc<PolicyCache> {
    use crate::policy_cache::{
        AgentFacts, BoundedSink, CacheSetup, FileRecordStore, PolicyStore, SignedEnvelopes,
    };
    use palisade_proto::policy_bundle::{
        EffectiveMode, Scope, Target, record::RecordKey, stale::StaleAfter,
    };
    let c = PolicyCache::new(CacheSetup {
        target: Target {
            tenant: TenantId(uuid(TENANT)),
            scope: Scope::Device(HostId(uuid(DEVICE))),
        },
        store: PolicyStore::open(dir.join("policy")).unwrap(),
        records: Box::new(FileRecordStore::open(dir.join("record")).unwrap()),
        key: RecordKey::from_bytes(&[3; 32]),
        verifier: Box::new(SignedEnvelopes::new(trust)),
        facts: AgentFacts::default(),
        events: Arc::new(BoundedSink::default()),
        mode: EffectiveMode::ENFORCE,
        stale_after: StaleAfter::DEFAULT,
        engine: palisade_policy::engine::EngineConfig::default(),
    });
    c.load_startup(now());
    Arc::new(c)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_agent_enrols_checks_in_and_takes_trust_sets_and_policy() {
    let env = start("ABCDEFGHJKMN").await;
    let dir = data_dir("e2e");
    let protector = MemoryProtector::new().unwrap();
    let config = CommsConfig {
        data_dir: dir.clone(),
        enrol: Some(enrol_config(&env, "ABCDEFGHJKMN", env.server.pki.pin())),
        proxy: None,
        no_proxy: Vec::new(),
    };
    let facts = device_facts("ws-01").unwrap();

    // Enrol and store the identity.
    let (identity, store) = load_or_enrol(&config, Box::new(protector), facts.clone(), now())
        .await
        .unwrap();
    assert_eq!(identity.device, HostId(uuid(DEVICE)));
    assert!(dir.join(identity::IDENTITY_FILE).exists());

    // Check in: nothing to update yet.
    let trust: SharedTrust = Arc::new(arc_swap::ArcSwap::from_pointee(
        TrustSet::new(1, now(), &[SignatureAlgorithm::EcdsaP384Sha384]).unwrap(),
    ));
    let policy_cache = cache(&dir, trust.clone());
    let mut ctx = context(
        &identity,
        store,
        &config,
        Some(trust.clone()),
        Some(policy_cache.clone()),
        now(),
    )
    .unwrap();
    assert_eq!(trust.load().trust_version(), 1);
    let round = ctx.round(now()).await;
    assert!(
        matches!(
            round,
            Round::Ok {
                trust_updated: false,
                policy_updated: false,
                ..
            }
        ),
        "{round:?}"
    );

    // The server publishes trust version 2 and a policy: the next round
    // takes both, through the anchor and the cache's own checks.
    let (hash, envelope) = policy_envelope(&env.server.pki, 7);
    {
        let mut s = env.server.state.lock().unwrap();
        s.trust_version = 2;
        s.policy = Some((7, hash, envelope));
    }
    let round = ctx.round(now()).await;
    assert!(
        matches!(
            round,
            Round::Ok {
                trust_updated: true,
                policy_updated: true,
                ..
            }
        ),
        "{round:?}"
    );
    assert_eq!(trust.load().trust_version(), 2);
    assert_eq!(policy_cache.current().policy_version(), 7);
    // And the next round finds nothing new.
    assert!(matches!(
        ctx.round(now()).await,
        Round::Ok {
            trust_updated: false,
            policy_updated: false,
            ..
        }
    ));

    assert_eq!(env.server.state.lock().unwrap().enrolments, 1);

    // Revoked: the next round stops.
    env.server
        .state
        .lock()
        .unwrap()
        .devices
        .values_mut()
        .for_each(|d| d.2 = true);
    assert_eq!(ctx.round(now()).await, Round::Rejected);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_pin_or_code_never_enrols() {
    let env = start("ABCDEFGHJKMN").await;
    let facts = device_facts("ws-01").unwrap();

    // Another CA's pin: the handshake fails as a pin mismatch, before the
    // code is sent.
    let wrong = enrol_config(&env, "ABCDEFGHJKMN", Sha256Hex::from_bytes([7; 32]));
    assert!(matches!(
        enrol::enrol(&wrong, facts.clone(), now()).await,
        Err(EnrolError::PinMismatch)
    ));
    assert_eq!(env.server.state.lock().unwrap().enrolments, 0);

    // The right pin, a wrong code: refused, and not worth retrying.
    let bad = enrol_config(&env, "ZZZZZZZZZZZZ", env.server.pki.pin());
    assert!(matches!(
        enrol::enrol(&bad, facts.clone(), now()).await,
        Err(EnrolError::Refused(ErrorCode::CodeRejected))
    ));

    // Not enrolled, and no code configured.
    let config = CommsConfig {
        data_dir: data_dir("none"),
        enrol: None,
        proxy: None,
        no_proxy: Vec::new(),
    };
    assert!(matches!(
        load_or_enrol(
            &config,
            Box::new(MemoryProtector::new().unwrap()),
            facts,
            now()
        )
        .await,
        Err(StartError::NotEnrolled)
    ));
}

/// A `CONNECT` proxy that tunnels to `target`, after checking the request.
async fn proxy(target: SocketAddr, seen: Arc<Mutex<Vec<String>>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                return;
            };
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if client.read(&mut byte).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                seen.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&head).into_owned());
                let mut upstream = tokio::net::TcpStream::connect(target).await.unwrap();
                client
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enrolment_works_through_a_connect_proxy_with_tls_end_to_end() {
    let env = start("ABCDEFGHJKMN").await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let proxy_addr = proxy(env.enrol_addr, seen.clone()).await;
    let mut config = enrol_config(&env, "ABCDEFGHJKMN", env.server.pki.pin());
    let mut p = Proxy::parse(&format!("http://127.0.0.1:{}", proxy_addr.port())).unwrap();
    p.authorization = Some("Basic dXNlcjpwdw==".to_owned());
    config.proxy = Some(p);
    let (identity, _) = enrol::enrol(&config, device_facts("ws-01").unwrap(), now())
        .await
        .unwrap();
    assert_eq!(identity.device, HostId(uuid(DEVICE)));
    let seen = seen.lock().unwrap();
    assert!(seen[0].starts_with(&format!(
        "CONNECT localhost:{} HTTP/1.1\r\n",
        env.enrol_addr.port()
    )));
    assert!(seen[0].contains("Proxy-Authorization: Basic dXNlcjpwdw==\r\n"));
    // The proxy saw only the tunnel request: the code went inside TLS.
    assert!(!seen[0].contains("ABCDEFGHJKMN"));
}

#[test]
fn a_tampered_reply_is_refused_before_anything_is_stored() {
    // The check runs on the parsed reply; build one by hand.
    let pki = Pki::new();
    let (key, _) = LeafKey::generate().unwrap();
    let (other, _) = LeafKey::generate().unwrap();
    let cert = LeafCertificate::device(
        &pki.signer,
        &pki.issuing,
        other.public_key(),
        HostId(uuid(DEVICE)),
        TenantId(uuid(TENANT)),
        window(0, 30),
    )
    .unwrap();
    let reply = |chain: Vec<Vec<u8>>, root: Vec<u8>| EnrolResponse {
        device_id: HostId(uuid(DEVICE)),
        tenant_id: TenantId(uuid(TENANT)),
        group_id: uuid(GROUP),
        chain: BoundedVec::new(chain.into_iter().map(|c| Base64::new(c).unwrap()).collect())
            .unwrap(),
        root_key: Base64::new(root).unwrap(),
        trust_set: Base64::new(pki.trust_sets[0].clone()).unwrap(),
        checkin_url: None,
    };
    let server = Endpoint::parse("https://localhost:1").unwrap();
    // A certificate for another key.
    let r = reply(
        vec![cert.der().to_vec()],
        pki.root.public_key().spki_der().to_vec(),
    );
    let err = enrol::check_reply(r, key, &pki.pin(), &server, now()).unwrap_err();
    assert!(err.to_string().contains("this device's key"), "{err}");
    // A root key that is not the pinned one.
    let (key, _) = LeafKey::generate().unwrap();
    let r = reply(
        vec![cert.der().to_vec()],
        other.public_key().spki_der().to_vec(),
    );
    let err = enrol::check_reply(r, key, &pki.pin(), &server, now()).unwrap_err();
    assert!(err.to_string().contains("CA pin"), "{err}");
}

#[test]
fn the_install_time_settings_parse_strictly() {
    let pin = format!("sha256/{}", "ab".repeat(32));
    let env = |pairs: &[(&str, &str)]| {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k: &str| map.get(k).cloned()
    };
    assert!(config_from_env(env(&[])).unwrap().is_none());
    let c = config_from_env(env(&[
        ("PALISADE_SERVER", "https://palisade.example:8443"),
        ("PALISADE_CA_PIN", &pin),
        ("PALISADE_REGCODE", "ABCD-EFGH-JKMN"),
        ("PALISADE_PROXY", "http://proxy:3128"),
        ("NO_PROXY", ".corp,localhost"),
        ("PALISADE_DATA_DIR", "/tmp/x"),
    ]))
    .unwrap()
    .unwrap();
    assert_eq!(c.data_dir, std::path::PathBuf::from("/tmp/x"));
    assert_eq!(c.no_proxy, vec![".corp".to_owned(), "localhost".to_owned()]);
    assert!(c.proxy.is_some());
    assert_eq!(c.enrol.unwrap().server.port, 8443);
    // Enrolled devices need no code.
    let c = config_from_env(env(&[
        ("PALISADE_SERVER", "https://p"),
        ("PALISADE_CA_PIN", &pin),
    ]))
    .unwrap()
    .unwrap();
    assert!(c.enrol.is_none());
    for bad in [
        vec![("PALISADE_SERVER", "https://p")],
        vec![
            ("PALISADE_SERVER", "http://p"),
            ("PALISADE_CA_PIN", pin.as_str()),
        ],
        vec![
            ("PALISADE_SERVER", "https://p"),
            ("PALISADE_CA_PIN", "sha256/xx"),
        ],
        vec![
            ("PALISADE_SERVER", "https://p"),
            ("PALISADE_CA_PIN", pin.as_str()),
            ("PALISADE_PROXY", "socks://p:1"),
        ],
    ] {
        assert!(config_from_env(env(&bad)).is_err(), "{bad:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_subsystem_enrols_checks_in_and_stops_cleanly() {
    use crate::subsystem::{Health, Subsystem as _};
    use subsystem::CommsSubsystem;
    let env = start("ABCDEFGHJKMN").await;
    let config = CommsConfig {
        data_dir: data_dir("subsystem"),
        enrol: Some(enrol_config(&env, "ABCDEFGHJKMN", env.server.pki.pin())),
        proxy: None,
        no_proxy: Vec::new(),
    };
    let protector: subsystem::ProtectorFactory = Box::new(|| {
        MemoryProtector::new().map(|p| Box::new(p) as Box<dyn crate::policy_cache::Protector>)
    });
    let sub = Arc::new(CommsSubsystem::new(
        config,
        protector,
        Arc::new(crate::platform::SystemClock),
        "ws-01".to_owned(),
    ));
    assert!(matches!(sub.health(), Health::Degraded(_)));
    let (ctx, stop) = crate::subsystem::test_context("comms");
    let task = tokio::spawn(Arc::clone(&sub).run(ctx));
    for _ in 0..200 {
        if sub.health() == Health::Healthy {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(sub.health(), Health::Healthy);
    assert_eq!(env.server.state.lock().unwrap().enrolments, 1);
    stop();
    task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_code_leaves_the_subsystem_unhealthy_without_retrying() {
    use crate::subsystem::{Health, Subsystem as _};
    use subsystem::CommsSubsystem;
    let env = start("ABCDEFGHJKMN").await;
    let config = CommsConfig {
        data_dir: data_dir("refused"),
        enrol: Some(enrol_config(&env, "ZZZZZZZZZZZZ", env.server.pki.pin())),
        proxy: None,
        no_proxy: Vec::new(),
    };
    let sub = Arc::new(CommsSubsystem::new(
        config,
        Box::new(|| {
            MemoryProtector::new().map(|p| Box::new(p) as Box<dyn crate::policy_cache::Protector>)
        }),
        Arc::new(crate::platform::SystemClock),
        "ws-01".to_owned(),
    ));
    let (ctx, stop) = crate::subsystem::test_context("comms");
    let task = tokio::spawn(Arc::clone(&sub).run(ctx));
    for _ in 0..200 {
        if matches!(sub.health(), Health::Unhealthy(_)) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        matches!(sub.health(), Health::Unhealthy(_)),
        "{:?}",
        sub.health()
    );
    stop();
    task.await.unwrap().unwrap();
}
