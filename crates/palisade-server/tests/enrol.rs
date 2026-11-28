//! Enrolment and check-in against a running development server, over real
//! TLS (#223, #62): the flow `palisade-agent` follows, driven by a minimal
//! client here.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use common::{HttpResponse, connect, free_ports, get_request, http1, temp_dir};
use palisade_proto::comms::{
    Base64, CheckIn, CheckInResponse, DeviceFacts, EnrolPayload, EnrolRequest, EnrolResponse,
    HealthSummary, KeyProtection,
};
use palisade_proto::events::{BoundedVec, DnsName, Name, Text, Timestamp};
use palisade_proto::pki::leaf_key::{LeafKey, Pkcs8};
use palisade_proto::pki::{SkewTolerance, SystemClock, TrustAnchor};
use palisade_server::config;
use palisade_server::enrol::EnrolSettings;
use palisade_server::enrol::dev::DevServer;
use palisade_server::server::{self, RunningServer, Server, Tuning};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore};

struct Env {
    dev: DevServer,
    running: RunningServer,
    admin: u16,
    agent: u16,
}

async fn start() -> Env {
    let dir = temp_dir("enrol");
    let [admin, agent] = free_ports();
    let dev = DevServer::create(
        &dir,
        &[DnsName::from_str("localhost").unwrap()],
        EnrolSettings {
            checkin_url: Some(format!("https://localhost:{agent}")),
            ..EnrolSettings::default()
        },
    )
    .unwrap();
    let toml = format!(
        "[tls]\ncert_file = {:?}\nkey_file = {:?}\n\
         [listen.admin]\nbind = \"127.0.0.1\"\nport = {admin}\n\
         [listen.agent]\nbind = \"127.0.0.1\"\nport = {agent}\nclient_ca_file = {:?}\n",
        dev.cert_file.display().to_string(),
        dev.key_file.display().to_string(),
        dev.agent_ca_file.display().to_string(),
    );
    let path = dir.join("server.toml");
    std::fs::write(&path, toml).unwrap();
    let cfg = config::load(&path, &[]).unwrap().config;
    let prepared = server::prepare(&cfg, &[]).unwrap();
    let running = Server::new(cfg, prepared)
        .with_tuning(Tuning {
            retry_min: Duration::from_millis(20),
            retry_max: Duration::from_millis(100),
            poll: Duration::from_millis(50),
            request_head_timeout: Duration::from_millis(2000),
        })
        .with_routes(config::ListenerKind::Admin, dev.service.admin_routes())
        .with_routes(config::ListenerKind::Agent, dev.service.agent_routes())
        .start();
    for _ in 0..200 {
        if running.health().readiness().ready {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Env {
        dev,
        running,
        admin,
        agent,
    }
}

fn roots(env: &Env) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    let root_pem = std::fs::read(&env.dev.root_file).unwrap();
    use rustls::pki_types::pem::PemObject;
    roots
        .add(CertificateDer::from_pem_slice(&root_pem).unwrap())
        .unwrap();
    roots
}

fn client(env: &Env, identity: Option<(Vec<Vec<u8>>, &Pkcs8)>) -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots(env));
    let cfg = match identity {
        None => builder.with_no_client_auth(),
        Some((chain, key)) => builder
            .with_client_auth_cert(
                chain.into_iter().map(CertificateDer::from).collect(),
                PrivatePkcs8KeyDer::from(key.expose().to_vec()).into(),
            )
            .unwrap(),
    };
    Arc::new(cfg)
}

fn post(path: &str, body: &[u8]) -> Vec<u8> {
    let mut r = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    r.extend_from_slice(body);
    r
}

async fn send(cfg: Arc<ClientConfig>, port: u16, request: &[u8]) -> Option<HttpResponse> {
    let mut s = connect(cfg, ([127, 0, 0, 1], port).into(), "localhost")
        .await
        .ok()?;
    let r = http1(&mut s, request).await;
    (r.status != 0).then_some(r)
}

fn facts() -> DeviceFacts {
    DeviceFacts {
        hostname: Text::new("ws-01").unwrap(),
        fqdn: None,
        os: Name::new("Windows 11").unwrap(),
        os_build: None,
        arch: None,
        smbios_uuid: None,
        serial: None,
        macs: BoundedVec::default(),
        domain: None,
        agent_version: Text::new("0.1.0").unwrap(),
    }
}

fn request(key: &LeafKey, code: &str, nonce: u8, created_at: Timestamp) -> Vec<u8> {
    let payload = EnrolPayload {
        code: Text::new(code).unwrap(),
        public_key: Base64::new(key.public_key().spki_der().to_vec()).unwrap(),
        key_protection: KeyProtection::Software,
        nonce: Base64::new(vec![nonce; 32]).unwrap(),
        created_at,
        facts: facts(),
    };
    serde_json::to_vec(&EnrolRequest::sign(&payload, key).unwrap()).unwrap()
}

fn now() -> Timestamp {
    use palisade_proto::pki::Clock;
    SystemClock.now()
}

fn check_in_body() -> Vec<u8> {
    serde_json::to_vec(&CheckIn {
        agent_version: Text::new("0.1.0").unwrap(),
        os_build: None,
        uptime_s: 1,
        policy_version: None,
        bundle_hash: None,
        trust_version: 1,
        health: HealthSummary::Healthy,
        ips: BoundedVec::default(),
    })
    .unwrap()
}

fn code_of(r: &HttpResponse) -> String {
    r.json()["code"].as_str().unwrap_or_default().to_owned()
}

#[tokio::test]
async fn a_device_enrols_checks_in_and_is_refused_once_revoked() {
    let env = start().await;
    let (key, pkcs8) = LeafKey::generate().unwrap();
    let code = env.dev.code.expose().to_lowercase();

    // Enrol over TLS, the server authenticated by the pinned root.
    let r = send(
        client(&env, None),
        env.admin,
        &post("/v1/enrol", &request(&key, &code, 1, now())),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200, "{}", r.body);
    let reply: EnrolResponse = serde_json::from_str(&r.body).unwrap();
    assert_eq!(reply.chain.len(), 2);
    assert_eq!(
        format!(
            "sha256/{}",
            palisade_proto::pki::spki_sha256(reply.root_key.as_bytes())
        ),
        env.dev.ca_pin
    );
    let root = palisade_proto::pki::PublicKey::from_spki_der(reply.root_key.as_bytes()).unwrap();
    let mut anchor = TrustAnchor::new(root, SkewTolerance::DEFAULT).unwrap();
    anchor.accept(reply.trust_set.as_bytes(), now()).unwrap();
    assert_eq!(
        reply.checkin_url.as_ref().map(ToString::to_string),
        Some(format!("https://localhost:{}", env.agent))
    );

    // The same request again is a replay.
    let replay = send(
        client(&env, None),
        env.admin,
        &post("/v1/enrol", &request(&key, &code, 1, now())),
    )
    .await
    .unwrap();
    assert_eq!(replay.status, 400);

    // Check in over mTLS with the issued certificate.
    let chain: Vec<Vec<u8>> = reply.chain.iter().map(|c| c.as_bytes().to_vec()).collect();
    let mtls = client(&env, Some((chain.clone(), &pkcs8)));
    let r = send(
        mtls.clone(),
        env.agent,
        &post("/v1/checkin", &check_in_body()),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200, "{}", r.body);
    let ci: CheckInResponse = serde_json::from_str(&r.body).unwrap();
    assert_eq!(ci.trust_version, 1);
    assert_eq!(ci.policy_version, None);
    assert!(env.dev.store.devices()[0].last_seen.is_some());

    // Nothing is published yet; the trust set is.
    let r = send(mtls.clone(), env.agent, &get_request("/v1/policy"))
        .await
        .unwrap();
    assert_eq!(r.status, 404);
    assert_eq!(code_of(&r), "not_found");
    let r = send(mtls.clone(), env.agent, &get_request("/v1/trust"))
        .await
        .unwrap();
    assert_eq!(r.status, 200);

    // The agent listener refuses a client without a certificate at the
    // handshake.
    assert!(
        send(
            client(&env, None),
            env.agent,
            &post("/v1/checkin", &check_in_body())
        )
        .await
        .is_none()
    );

    // Revoke: the next request is refused, with no CRL delay.
    let id = env.dev.store.devices()[0].device;
    use palisade_server::enrol::EnrolStore as _;
    assert!(env.dev.store.revoke_device(id));
    let r = send(mtls, env.agent, &post("/v1/checkin", &check_in_body()))
        .await
        .unwrap();
    assert_eq!(r.status, 403);
    assert_eq!(code_of(&r), "device_rejected");
    env.running.shutdown().await;
}

#[tokio::test]
async fn bad_codes_stale_requests_and_floods_are_refused() {
    let env = start().await;
    let (key, _) = LeafKey::generate().unwrap();
    let cfg = client(&env, None);

    let r = send(
        cfg.clone(),
        env.admin,
        &post("/v1/enrol", &request(&key, "ZZZZ-ZZZZ-ZZZZ", 1, now())),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 403);
    assert_eq!(code_of(&r), "code_rejected");
    assert!(!r.body.contains("ZZZZ"));

    let stale = Timestamp::from_unix_micros(now().unix_micros() - 3600 * 1_000_000).unwrap();
    let r = send(
        cfg.clone(),
        env.admin,
        &post("/v1/enrol", &request(&key, env.dev.code.expose(), 2, stale)),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 400);
    assert_eq!(code_of(&r), "bad_request");

    let r = send(cfg.clone(), env.admin, &post("/v1/enrol", b"{not json"))
        .await
        .unwrap();
    assert_eq!(r.status, 400);

    // Ten a minute from one source; three were spent above.
    let mut limited = None;
    for n in 0..10u8 {
        let r = send(
            cfg.clone(),
            env.admin,
            &post("/v1/enrol", &request(&key, "ZZZZ-ZZZZ-ZZZZ", 10 + n, now())),
        )
        .await
        .unwrap();
        if r.status == 429 {
            limited = Some(r);
            break;
        }
    }
    let r = limited.expect("the source limit must apply");
    assert_eq!(code_of(&r), "rate_limited");
    assert!(r.header("retry-after").is_some());
    assert!(env.dev.store.devices().is_empty());
    env.running.shutdown().await;
}

#[tokio::test]
async fn a_certificate_from_the_ca_that_is_not_a_device_record_is_refused() {
    let env = start().await;
    // Issue a certificate straight from the authority, without enrolling:
    // the handshake passes (right CA), but no device record matches.
    let (key, pkcs8) = LeafKey::generate().unwrap();
    let id = palisade_proto::events::HostId(
        palisade_proto::events::Uuid7::from_str("019a0000-0000-7000-8000-000000000099").unwrap(),
    );
    let tenant = palisade_proto::events::TenantId(
        palisade_proto::events::Uuid7::from_str(palisade_server::enrol::dev::DEV_TENANT).unwrap(),
    );
    let cert = env
        .dev
        .authority
        .issue_device(key.public_key(), id, tenant, now(), 1)
        .unwrap();
    let mut chain = vec![cert.der().to_vec()];
    chain.extend(env.dev.authority.chain());
    let r = send(
        client(&env, Some((chain, &pkcs8))),
        env.agent,
        &post("/v1/checkin", &check_in_body()),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 403);
    assert_eq!(code_of(&r), "device_rejected");
    env.running.shutdown().await;
}
