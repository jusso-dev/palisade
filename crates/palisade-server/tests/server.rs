//! In-process tests of the running server over real TLS connections.

// Test helpers outside `#[test]` functions unwrap freely.
#![allow(clippy::unwrap_used)]

mod common;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use common::*;
use palisade_server::config::{self, Config, ListenerKind};
use palisade_server::net::HostAddr;
use palisade_server::server::{self, RunningServer, Server, ShutdownOutcome, Tuning};
use rustls::crypto::ring::cipher_suite as cs;
use rustls::version::{TLS12, TLS13};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const ADMIN_ONLY: &str =
    "[listen.agent]\nbind = \"127.0.0.1\"\nport = {agent}\nclient_ca_file = \"agent-ca.crt\"\n";

fn fast() -> Tuning {
    Tuning {
        retry_min: Duration::from_millis(20),
        retry_max: Duration::from_millis(100),
        poll: Duration::from_millis(50),
    }
}

struct Ports {
    admin: u16,
    agent: u16,
}

fn base_config(pki: &Pki, extra: &str) -> (Config, Ports) {
    let ports = Ports {
        admin: free_port(),
        agent: free_port(),
    };
    let body = format!(
        "[listen.admin]\nbind = \"127.0.0.1\"\nport = {}\n{}\n{extra}",
        ports.admin,
        ADMIN_ONLY.replace("{agent}", &ports.agent.to_string()),
    );
    let path = write_config(pki, &body);
    let cfg = config::load(&path, &[]).unwrap().config;
    (cfg, ports)
}

fn start(cfg: Config, routes: Option<Router>) -> RunningServer {
    let prepared = server::prepare(&cfg, &[]).unwrap();
    let mut s = Server::new(cfg, prepared).with_tuning(fast());
    if let Some(r) = routes {
        s = s.with_routes(ListenerKind::Admin, r);
    }
    s.start()
}

async fn wait_ready(running: &RunningServer) {
    for _ in 0..200 {
        if running.health().readiness().ready {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "server never became ready: {:?}",
        running.health().readiness()
    );
}

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

async fn admin_get(pki: &Pki, port: u16, path: &str) -> HttpResponse {
    let cfg = client_config(pki, &[&TLS13, &TLS12], None, &[b"http/1.1"]);
    let mut s = connect(cfg, addr(port), "localhost").await.unwrap();
    http1(&mut s, &get_request(path)).await
}

#[tokio::test]
async fn probes_answer_over_tls_with_request_ids() {
    let pki = pki("probes", &["localhost"]);
    let (cfg, ports) = base_config(&pki, "");
    let running = start(cfg, None);
    wait_ready(&running).await;

    let r = admin_get(&pki, ports.admin, "/healthz").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), serde_json::json!({ "status": "alive" }));
    assert_eq!(r.header("palisade-request-id").unwrap().len(), 32);

    let r = admin_get(&pki, ports.admin, "/readyz").await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["status"], "ready");

    let r = admin_get(&pki, ports.admin, "/no/such/route").await;
    assert_eq!(r.status, 404);
    assert_eq!(
        r.header("content-type").unwrap(),
        "application/problem+json"
    );
    assert_eq!(
        r.json()["request_id"],
        r.header("palisade-request-id").unwrap()
    );

    assert_eq!(running.shutdown().await, ShutdownOutcome::Drained);
}

#[tokio::test]
async fn tls12_aead_is_accepted_and_tls13_preferred() {
    let pki = pki("tls12", &["localhost"]);
    let (cfg, ports) = base_config(&pki, "");
    let running = start(cfg, None);
    wait_ready(&running).await;

    let both = client_config(&pki, &[&TLS13, &TLS12], None, &[]);
    let s = connect(both, addr(ports.admin), "localhost").await.unwrap();
    assert_eq!(
        s.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );

    let only12 = client_config(&pki, &[&TLS12], None, &[]);
    let s = connect(only12, addr(ports.admin), "localhost")
        .await
        .unwrap();
    let conn = s.get_ref().1;
    assert_eq!(
        conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_2)
    );
    let suite = format!("{:?}", conn.negotiated_cipher_suite().unwrap().suite());
    assert!(suite.contains("_GCM_"), "{suite}");
    running.shutdown().await;
}

#[tokio::test]
async fn min_version_13_rejects_tls12() {
    let pki = pki("tls13only", &["localhost"]);
    let (cfg, ports) = base_config(&pki, "");
    let mut cfg = cfg;
    cfg.tls.min_version = config::TlsVersion::Tls13;
    let running = start(cfg, None);
    wait_ready(&running).await;
    let only12 = client_config(&pki, &[&TLS12], None, &[]);
    assert!(
        connect(only12, addr(ports.admin), "localhost")
            .await
            .is_err()
    );
    running.shutdown().await;
}

#[tokio::test]
async fn chacha_only_client_is_rejected() {
    let pki = pki("chacha", &["localhost"]);
    let (cfg, ports) = base_config(&pki, "");
    let running = start(cfg, None);
    wait_ready(&running).await;
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = vec![
        cs::TLS13_CHACHA20_POLY1305_SHA256,
        cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        cs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];
    let cfg = client_with_provider(&pki, provider);
    assert!(connect(cfg, addr(ports.admin), "localhost").await.is_err());
    running.shutdown().await;
}

#[tokio::test]
async fn strict_profile_rejects_aes128_and_p256() {
    let pki = pki("strict", &["localhost"]);
    let (mut cfg, ports) = base_config(&pki, "");
    cfg.tls.profile = config::CryptoProfile::AsdStrict;
    let running = start(cfg, None);
    wait_ready(&running).await;

    let mut aes128 = rustls::crypto::ring::default_provider();
    aes128.cipher_suites = vec![cs::TLS13_AES_128_GCM_SHA256];
    assert!(
        connect(
            client_with_provider(&pki, aes128),
            addr(ports.admin),
            "localhost"
        )
        .await
        .is_err()
    );

    let mut x25519 = rustls::crypto::ring::default_provider();
    x25519.kx_groups = vec![rustls::crypto::ring::kx_group::X25519];
    assert!(
        connect(
            client_with_provider(&pki, x25519),
            addr(ports.admin),
            "localhost"
        )
        .await
        .is_err()
    );

    let ok = client_config(&pki, &[&TLS13], None, &[]);
    let s = connect(ok, addr(ports.admin), "localhost").await.unwrap();
    let suite = format!(
        "{:?}",
        s.get_ref().1.negotiated_cipher_suite().unwrap().suite()
    );
    assert_eq!(suite, "TLS13_AES_256_GCM_SHA384");
    running.shutdown().await;
}

fn client_with_provider(
    pki: &Pki,
    provider: rustls::crypto::CryptoProvider,
) -> Arc<rustls::ClientConfig> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(pki.ca_pem.as_bytes()).unwrap())
        .unwrap();
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// A hand-built TLS 1.1 ClientHello (no supported_versions extension).
fn tls11_client_hello() -> Vec<u8> {
    let mut body = vec![0x03, 0x02];
    body.extend_from_slice(&[0x42; 32]);
    body.push(0); // session id
    body.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]); // TLS_RSA_WITH_AES_128_CBC_SHA
    body.extend_from_slice(&[0x01, 0x00]); // null compression
    let mut hs = vec![0x01, 0x00];
    hs.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&u16::try_from(hs.len()).unwrap().to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

#[tokio::test]
async fn tls10_and_11_and_plaintext_are_rejected() {
    let pki = pki("legacy", &["localhost"]);
    let (cfg, ports) = base_config(&pki, "");
    let running = start(cfg, None);
    wait_ready(&running).await;

    let mut tcp = TcpStream::connect(addr(ports.admin)).await.unwrap();
    tcp.write_all(&tls11_client_hello()).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut buf)).await;
    assert!(
        buf.first() != Some(&0x16),
        "server answered a TLS 1.1 hello with a handshake: {buf:02x?}"
    );
    assert!(
        buf.is_empty() || buf[0] == 0x15,
        "expected an alert or close: {buf:02x?}"
    );

    let mut tcp = TcpStream::connect(addr(ports.admin)).await.unwrap();
    tcp.write_all(&get_request("/healthz")).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut buf)).await;
    assert!(!String::from_utf8_lossy(&buf).contains("HTTP/1.1 200"));
    running.shutdown().await;
}

#[tokio::test]
async fn agent_listener_requires_a_client_certificate_from_the_agent_ca() {
    let pki = pki("mtls", &["localhost"]);
    let (cfg, ports) = base_config(&pki, "");
    let running = start(cfg, None);
    wait_ready(&running).await;

    async fn try_get(cfg: Arc<rustls::ClientConfig>, port: u16) -> Option<HttpResponse> {
        let mut s = connect(cfg, addr(port), "localhost").await.ok()?;
        s.write_all(&get_request("/healthz")).await.ok()?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.ok()?;
        let r = parse_response(&buf);
        (r.status != 0).then_some(r)
    }

    let none = client_config(&pki, &[&TLS13, &TLS12], None, &[]);
    assert!(
        try_get(none, ports.agent).await.is_none(),
        "no client cert must fail"
    );

    let none12 = client_config(&pki, &[&TLS12], None, &[]);
    assert!(
        try_get(none12, ports.agent).await.is_none(),
        "no client cert must fail on TLS 1.2"
    );

    let rogue = client_config(
        &pki,
        &[&TLS13],
        Some((&pki.other_client_cert_pem, &pki.other_client_key_pem)),
        &[],
    );
    assert!(
        try_get(rogue, ports.agent).await.is_none(),
        "foreign CA must fail"
    );

    let good = client_config(
        &pki,
        &[&TLS13],
        Some((&pki.client_cert_pem, &pki.client_key_pem)),
        &[],
    );
    let r = try_get(good, ports.agent)
        .await
        .expect("enrolled cert must work");
    assert_eq!(r.status, 200);

    // The admin listener does not ask for a client certificate.
    let r = admin_get(&pki, ports.admin, "/healthz").await;
    assert_eq!(r.status, 200);
    running.shutdown().await;
}

#[tokio::test]
async fn http2_is_negotiated_by_alpn() {
    let pki = pki("h2", &["localhost"]);
    let (cfg, ports) = base_config(&pki, "");
    let running = start(cfg, None);
    wait_ready(&running).await;
    let cfg = client_config(&pki, &[&TLS13], None, &[b"h2", b"http/1.1"]);
    let mut s = connect(cfg, addr(ports.admin), "localhost").await.unwrap();
    assert_eq!(s.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    // Connection preface plus an empty SETTINGS frame; the server must
    // answer with its own SETTINGS frame.
    let mut preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    preface.extend_from_slice(&[0, 0, 0, 0x04, 0, 0, 0, 0, 0]);
    s.write_all(&preface).await.unwrap();
    let mut header = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut header))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(header[3], 0x04, "first server frame must be SETTINGS");
    // Graceful HTTP/2 shutdown sends GOAWAY plus a PING and waits for the
    // answer. This raw client never reads, so it would hold the drain until
    // the grace period ends; it hangs up instead.
    drop(s);
    assert_eq!(running.shutdown().await, ShutdownOutcome::Drained);
}

#[tokio::test]
async fn body_limits_apply_to_declared_and_streamed_bodies() {
    let pki = pki("limits", &["localhost"]);
    let (mut cfg, ports) = base_config(&pki, "");
    for l in &mut cfg.listeners {
        l.body_limit = 1024;
    }
    let echo = Router::new().route(
        "/echo",
        axum::routing::post(|b: axum::body::Bytes| async move { b.len().to_string() }),
    );
    let running = start(cfg, Some(echo));
    wait_ready(&running).await;
    let client = client_config(&pki, &[&TLS13], None, &[]);

    let mut s = connect(client.clone(), addr(ports.admin), "localhost")
        .await
        .unwrap();
    let req = format!(
        "POST /echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 2048\r\n\r\n{}",
        "a".repeat(2048)
    );
    let r = http1(&mut s, req.as_bytes()).await;
    assert_eq!(r.status, 413, "{}", r.head);
    assert_eq!(
        r.json()["type"],
        "https://palisade.dev/problems/payload-too-large"
    );

    let mut s = connect(client.clone(), addr(ports.admin), "localhost")
        .await
        .unwrap();
    let chunk = "a".repeat(600);
    let req = format!(
        "POST /echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n258\r\n{chunk}\r\n258\r\n{chunk}\r\n0\r\n\r\n"
    );
    let r = http1(&mut s, req.as_bytes()).await;
    assert_eq!(r.status, 413, "{}", r.head);
    assert_eq!(
        r.header("content-type").unwrap(),
        "application/problem+json"
    );

    let mut s = connect(client, addr(ports.admin), "localhost")
        .await
        .unwrap();
    let req = format!(
        "POST /echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 1000\r\n\r\n{}",
        "a".repeat(1000)
    );
    let r = http1(&mut s, req.as_bytes()).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, "1000");
    running.shutdown().await;
}

#[tokio::test]
async fn shutdown_drains_in_flight_requests_and_stops_accepting() {
    let pki = pki("drain", &["localhost"]);
    let (cfg, ports) = base_config(&pki, "[shutdown]\ngrace_secs = 10\n");
    let slow = Router::new().route(
        "/slow",
        get(|| async {
            tokio::time::sleep(Duration::from_millis(400)).await;
            "done"
        }),
    );
    let running = start(cfg, Some(slow));
    wait_ready(&running).await;

    let client = client_config(&pki, &[&TLS13], None, &[]);
    let mut s = connect(client.clone(), addr(ports.admin), "localhost")
        .await
        .unwrap();
    s.write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    s.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let health = running.health().clone();
    let shutdown = tokio::spawn(running.shutdown());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!health.readiness().ready);
    assert_eq!(health.readiness().body["status"], "shutting_down");
    assert!(
        TcpStream::connect(addr(ports.admin)).await.is_err(),
        "listener must be closed while draining"
    );

    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let r = parse_response(&buf);
    assert_eq!(r.status, 200);
    assert_eq!(r.body, "done");
    assert_eq!(shutdown.await.unwrap(), ShutdownOutcome::Drained);
}

#[tokio::test]
async fn shutdown_forces_after_grace() {
    let pki = pki("force", &["localhost"]);
    let (cfg, ports) = base_config(&pki, "[shutdown]\ngrace_secs = 1\n");
    let stuck = Router::new().route(
        "/stuck",
        get(|| async {
            tokio::time::sleep(Duration::from_secs(20)).await;
            "late"
        }),
    );
    let running = start(cfg, Some(stuck));
    wait_ready(&running).await;
    let client = client_config(&pki, &[&TLS13], None, &[]);
    let mut s = connect(client, addr(ports.admin), "localhost")
        .await
        .unwrap();
    s.write_all(b"GET /stuck HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    s.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let started = std::time::Instant::now();
    assert_eq!(running.shutdown().await, ShutdownOutcome::Forced);
    assert!(started.elapsed() < Duration::from_secs(5));
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf).await;
    assert!(!String::from_utf8_lossy(&buf).contains("late"));
}

/// An address source the test can change while the server runs.
#[derive(Default)]
struct FakeHost {
    addrs: Mutex<Vec<HostAddr>>,
    fail: AtomicBool,
}

impl FakeHost {
    fn set(&self, addrs: Vec<HostAddr>) {
        *self.addrs.lock().unwrap() = addrs;
    }

    fn source(self: &Arc<Self>) -> server::AddrSource {
        let me = self.clone();
        Arc::new(move || {
            if me.fail.load(Ordering::Relaxed) {
                return Err(std::io::Error::other("listing failed"));
            }
            Ok(me.addrs.lock().unwrap().clone())
        })
    }
}

fn host_addr(iface: &str, ip: &str) -> HostAddr {
    HostAddr {
        interface: iface.into(),
        ip: ip.parse().unwrap(),
        scope_id: 0,
    }
}

#[tokio::test]
async fn named_interface_that_appears_late_is_bound_and_followed() {
    let pki = pki("late-iface", &["localhost"]);
    let (mut cfg, ports) = base_config(&pki, "");
    cfg.listeners[0].bind = config::BindTarget::Interface("overlay0".into());
    let fake = Arc::new(FakeHost::default());
    let prepared = server::prepare(&cfg, &[]).unwrap();
    let running = Server::new(cfg, prepared)
        .with_tuning(fast())
        .with_addr_source(fake.source())
        .start();

    tokio::time::sleep(Duration::from_millis(150)).await;
    let r = running.health().readiness();
    assert!(!r.ready);
    assert_eq!(
        r.body["indicators"],
        serde_json::json!(["listener_unbound:admin"])
    );
    assert!(TcpStream::connect(addr(ports.admin)).await.is_err());

    fake.set(vec![host_addr("overlay0", "127.0.0.1")]);
    wait_ready(&running).await;
    let r = admin_get(&pki, ports.admin, "/healthz").await;
    assert_eq!(r.status, 200);

    // The interface loses its address: the socket closes and the listener
    // reports unbound again.
    fake.set(vec![]);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!running.health().readiness().ready);
    assert!(TcpStream::connect(addr(ports.admin)).await.is_err());

    // A failing interface listing counts as "no address", not a crash.
    fake.fail.store(true, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!running.health().readiness().ready);
    fake.fail.store(false, Ordering::Relaxed);

    fake.set(vec![host_addr("overlay0", "127.0.0.1")]);
    wait_ready(&running).await;
    assert_eq!(running.shutdown().await, ShutdownOutcome::Drained);
}

#[tokio::test]
async fn port_in_use_is_retried_until_free() {
    let pki = pki("busy", &["localhost"]);
    let (cfg, ports) = base_config(&pki, "");
    let blocker = std::net::TcpListener::bind(addr(ports.admin)).unwrap();
    let running = start(cfg, None);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!running.health().readiness().ready);
    drop(blocker);
    wait_ready(&running).await;
    assert_eq!(admin_get(&pki, ports.admin, "/healthz").await.status, 200);
    running.shutdown().await;
}

#[tokio::test]
async fn overlay_profile_flags_public_exposure_in_health() {
    let pki = pki("exposure", &["localhost"]);
    let (mut cfg, ports) = base_config(&pki, "[deployment]\nprofile = \"overlay\"\n");
    cfg.listeners[0].bind = config::BindTarget::Ip("0.0.0.0".parse().unwrap());
    let fake = Arc::new(FakeHost::default());
    fake.set(vec![
        host_addr("lo", "127.0.0.1"),
        host_addr("eth0", "8.8.4.4"),
        host_addr("overlay0", "100.64.0.9"),
    ]);
    let warnings = server::placement_warnings(&cfg, &fake.addrs.lock().unwrap());
    assert!(
        warnings.iter().any(|w| w.contains("8.8.4.4")),
        "{warnings:?}"
    );
    let prepared = server::prepare(&cfg, &[]).unwrap();
    let running = Server::new(cfg, prepared)
        .with_tuning(fast())
        .with_addr_source(fake.source())
        .start();
    wait_ready(&running).await;
    let r = running.health().readiness();
    assert!(r.ready, "exposure degrades but does not fail readiness");
    assert_eq!(r.body["status"], "degraded");
    assert_eq!(
        r.body["indicators"],
        serde_json::json!(["public_exposure:admin"])
    );
    assert_eq!(admin_get(&pki, ports.admin, "/healthz").await.status, 200);
    running.shutdown().await;
}

#[tokio::test]
async fn connection_cap_holds_extra_clients_in_the_backlog() {
    let pki = pki("cap", &["localhost"]);
    let (mut cfg, ports) = base_config(&pki, "");
    cfg.listeners[0].max_connections = 1;
    let running = start(cfg, None);
    wait_ready(&running).await;
    let client = client_config(&pki, &[&TLS13], None, &[]);
    let held = connect(client.clone(), addr(ports.admin), "localhost")
        .await
        .unwrap();
    let second = tokio::time::timeout(
        Duration::from_millis(300),
        connect(client.clone(), addr(ports.admin), "localhost"),
    )
    .await;
    assert!(
        second.is_err(),
        "second handshake must wait while the cap is reached"
    );
    drop(held);
    let mut s = tokio::time::timeout(
        Duration::from_secs(5),
        connect(client, addr(ports.admin), "localhost"),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(http1(&mut s, &get_request("/healthz")).await.status, 200);
    running.shutdown().await;
}

#[test]
fn prepare_checks_public_url_against_sans() {
    let pki = pki(
        "sans",
        &["palisade-server.overlay.test", "100.64.0.7", "fd7a::7"],
    );
    let body = |admin_url: &str, agent_url: &str| {
        format!(
            "[listen.admin]\nbind = \"127.0.0.1\"\nport = 1\npublic_url = \"{admin_url}\"\n\
             [listen.agent]\nbind = \"127.0.0.1\"\nport = 2\npublic_url = \"{agent_url}\"\nclient_ca_file = \"agent-ca.crt\"\n"
        )
    };
    let load = |b: String| {
        let p = write_config(&pki, &b);
        config::load(&p, &[]).unwrap().config
    };
    let ok = load(body(
        "https://palisade-server.overlay.test:8443",
        "https://[fd7a::7]:8444",
    ));
    server::prepare(&ok, &[]).unwrap();
    let ok = load(body("https://100.64.0.7:8443", "https://100.64.0.7"));
    server::prepare(&ok, &[]).unwrap();

    let bad = load(body("https://console.example.test", "https://100.64.0.8"));
    let errors = server::prepare(&bad, &[]).unwrap_err();
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert!(errors[0].contains("listen.admin.public_url"), "{errors:?}");
    assert!(errors[1].contains("listen.agent.public_url"), "{errors:?}");
}

#[test]
fn prepare_reports_bad_tls_files_without_key_contents() {
    let pki = pki("badtls", &["localhost"]);
    let (cfg, _) = base_config(&pki, "");
    // A key file that is not a key, with recognisable content.
    write_secret(
        &pki.server_key,
        "-----BEGIN NOT A KEY-----\nc2VudGluZWwtc2VjcmV0\n-----END NOT A KEY-----\n",
    );
    let e = server::prepare(&cfg, &[]).unwrap_err().join("\n");
    assert!(e.contains("server.key"), "{e}");
    assert!(!e.contains("c2VudGluZWwtc2VjcmV0"), "{e}");

    // A key that does not match the certificate.
    write_secret(&pki.server_key, &common::x509::Key::generate().pem());
    let e = server::prepare(&cfg, &[]).unwrap_err().join("\n");
    assert!(
        e.contains("do not form a usable certificate and key"),
        "{e}"
    );

    // A missing agent CA bundle.
    std::fs::remove_file(&pki.agent_ca).unwrap();
    let pki2 = common::pki("badca", &["localhost"]);
    let (mut cfg2, _) = base_config(&pki2, "");
    std::fs::remove_file(&pki2.agent_ca).unwrap();
    cfg2.listeners[1].client_ca_file = Some(Path::new(&pki2.agent_ca).to_path_buf());
    let e = server::prepare(&cfg2, &[]).unwrap_err().join("\n");
    assert!(
        e.contains("listen.agent") && e.contains("agent-ca.crt"),
        "{e}"
    );
}
