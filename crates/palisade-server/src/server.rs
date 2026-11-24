//! The running server: listener supervision, connections and shutdown.
//!
//! Each configured listener has a supervisor task. The supervisor resolves
//! the listener's bind target to socket addresses, binds each one it does
//! not have yet, and runs an accept loop per bound socket. It repeats this
//! on a timer, so:
//!
//! - an address that cannot be bound yet (an overlay interface that is not
//!   up, an address not assigned yet, a port still in use) is retried with
//!   exponential backoff, and health shows `listener_unbound:<name>` until
//!   it succeeds;
//! - a named interface that gains or loses addresses while the server runs
//!   is followed: new addresses are bound, vanished ones stop accepting;
//! - two listeners whose targets resolve to the same address (an interface
//!   and a literal) are rejected before start by [`prepare`].
//!
//! Connections are TLS only. ALPN offers `h2` and `http/1.1`; a connection
//! that negotiated `h2` is served as HTTP/2 only, and every other connection
//! (including one with no ALPN) as HTTP/1.1 only. A client must send its
//! first complete request within the request-head timeout (30 s) of the
//! handshake, or the connection is closed, so an idle or stalled client
//! cannot hold a connection slot. A listener serves at most
//! `max_connections` connections at a time; further clients wait in the
//! TCP backlog.
//!
//! Shutdown has two phases. **Draining**: listeners stop accepting,
//! readiness fails, and every open connection is asked to finish its
//! in-flight requests and close (HTTP/1.1 closes after the current
//! response, HTTP/2 sends GOAWAY). If connections remain when
//! `shutdown.grace_secs` runs out, **force**: they are dropped.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::Router;
use axum::http::Request;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::{AbortHandle, JoinSet};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

use crate::config::{BindTarget, Config, ListenerKind, ListenerSettings, Profile};
use crate::health::{Health, ListenerHealth};
use crate::http::{self, Peer};
use crate::net::{self, HostAddr};
use crate::tls::{self, Identity};

/// Time allowed for a client to complete the TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// HTTP/1.1 read buffer, which bounds the size of a request head.
const H1_MAX_BUF: usize = 64 * 1024;
/// HTTP/2 limits.
const H2_MAX_STREAMS: u32 = 128;
const H2_MAX_HEADER_LIST: u32 = 64 * 1024;
const H2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const H2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(20);
/// Listen backlog.
const BACKLOG: i32 = 1024;
/// Time allowed for dropped connections to finish unwinding after force.
const FORCE_SETTLE: Duration = Duration::from_secs(2);
/// ALPN protocols offered, in preference order.
const ALPN: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// Where the supervisor gets the host's interface addresses from.
pub type AddrSource = Arc<dyn Fn() -> std::io::Result<Vec<HostAddr>> + Send + Sync>;

/// Supervisor timings.
#[derive(Debug, Clone, Copy)]
pub struct Tuning {
    /// First retry delay for an unbound listener.
    pub retry_min: Duration,
    /// Longest retry delay.
    pub retry_max: Duration,
    /// How often a fully bound listener re-checks its interface addresses.
    pub poll: Duration,
    /// Time allowed for a client to send a complete request head: the first
    /// one after the TLS handshake (HTTP/1.1 and HTTP/2), and each later one
    /// on a kept-alive HTTP/1.1 connection.
    pub request_head_timeout: Duration,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            retry_min: Duration::from_secs(1),
            retry_max: Duration::from_secs(30),
            poll: Duration::from_secs(5),
            request_head_timeout: Duration::from_secs(30),
        }
    }
}

/// Everything checked before the server binds a socket: the TLS identity
/// loads, each listener's TLS configuration builds, and every `public_url`
/// host is in the certificate. `check-config` runs the same checks.
pub struct Prepared {
    tls: BTreeMap<ListenerKind, Arc<ServerConfig>>,
    /// Non-fatal findings, such as placement warnings.
    pub warnings: Vec<String>,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prepared")
            .field("listeners", &self.tls.keys().collect::<Vec<_>>())
            .field("warnings", &self.warnings)
            .finish()
    }
}

/// Runs the pre-start checks. `host` is the current interface list, used
/// for the placement warnings. Returns every error found.
pub fn prepare(config: &Config, host: &[HostAddr]) -> Result<Prepared, Vec<String>> {
    let identity = Identity::load(&config.tls).map_err(|e| vec![e])?;
    let mut errors = Vec::new();
    let mut tls_configs = BTreeMap::new();
    for l in &config.listeners {
        match tls::server_config(&config.tls, &identity, l.client_ca_file.as_deref(), &ALPN) {
            Ok(c) => {
                tls_configs.insert(l.kind, c);
            }
            Err(e) => errors.push(format!("listen.{}: {e}", l.kind)),
        }
        if let Some(url) = &l.public_url {
            if let Err(e) = tls::leaf_covers(&identity, &url.host) {
                errors.push(format!(
                    "listen.{}.public_url: host of {} is not in the subject alternative names of {} ({e})",
                    l.kind,
                    url.url,
                    config.tls.cert_file.display()
                ));
            }
        }
    }
    errors.extend(resolved_overlaps(config, host));
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(Prepared {
        tls: tls_configs,
        warnings: placement_warnings(config, host),
    })
}

/// Listeners whose bind targets resolve to the same socket address on this
/// host, for example `bind = "lo"` and `bind = "127.0.0.1"` on one port. The
/// static check in the configuration catches literal clashes; this one needs
/// the interface list.
fn resolved_overlaps(config: &Config, host: &[HostAddr]) -> Vec<String> {
    let mut seen: BTreeMap<SocketAddr, ListenerKind> = BTreeMap::new();
    let mut errors = Vec::new();
    for l in &config.listeners {
        for addr in net::resolve(&l.bind, l.port, host) {
            match seen.get(&addr) {
                Some(other) if *other != l.kind => errors.push(format!(
                    "listen.{other} and listen.{} both resolve to {addr}; give each listener its own address or port",
                    l.kind
                )),
                _ => {
                    seen.insert(addr, l.kind);
                }
            }
        }
    }
    errors
}

/// Placement warnings for `deployment.profile = "overlay"`: a listener that
/// binds every interface, binds a public address, or (for metrics) is not
/// on loopback.
pub fn placement_warnings(config: &Config, host: &[HostAddr]) -> Vec<String> {
    if config.profile != Profile::Overlay {
        return Vec::new();
    }
    let mut out = Vec::new();
    for l in &config.listeners {
        let name = l.kind;
        let addrs = net::resolve(&l.bind, l.port, host);
        if let BindTarget::Ip(ip) = l.bind {
            if ip.is_unspecified() {
                out.push(format!(
                    "listen.{name}: binds every interface ({ip}) under deployment.profile = \"overlay\"; bind the overlay address or interface instead"
                ));
            }
        }
        if let BindTarget::Interface(iface) = &l.bind {
            if addrs.is_empty() {
                out.push(format!(
                    "listen.{name}: interface {iface} has no address now; the server will keep retrying until it appears"
                ));
            }
        }
        let public = public_addrs(&addrs, host);
        if !public.is_empty() {
            out.push(format!(
                "listen.{name}: reachable on public address(es) {} under deployment.profile = \"overlay\"",
                join_ips(&public)
            ));
        }
        if name == ListenerKind::Metrics && addrs.iter().any(|a| !a.ip().is_loopback()) {
            out.push(
                "listen.metrics: not bound to loopback under deployment.profile = \"overlay\"; bind it to 127.0.0.1 or ::1".to_owned(),
            );
        }
    }
    out
}

fn public_addrs(bound: &BTreeSet<SocketAddr>, host: &[HostAddr]) -> Vec<IpAddr> {
    let set: BTreeSet<IpAddr> = bound
        .iter()
        .flat_map(|a| net::reachable_on(a, host))
        .filter(|ip| net::is_public(*ip))
        .collect();
    set.into_iter().collect()
}

fn join_ips(ips: &[IpAddr]) -> String {
    ips.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The shutdown phase, broadcast to every task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Running,
    Draining,
    Force,
}

/// A server ready to start.
pub struct Server {
    config: Arc<Config>,
    prepared: Prepared,
    routes: BTreeMap<ListenerKind, Router>,
    addrs: AddrSource,
    tuning: Tuning,
}

impl Server {
    /// A server for `config`, using the TLS configuration from [`prepare`].
    pub fn new(config: Config, prepared: Prepared) -> Self {
        Self {
            config: Arc::new(config),
            prepared,
            routes: BTreeMap::new(),
            addrs: Arc::new(net::host_addrs),
            tuning: Tuning::default(),
        }
    }

    /// Adds routes to one listener, next to the built-in probes. The
    /// middleware stack applies to them too.
    #[must_use]
    pub fn with_routes(mut self, kind: ListenerKind, router: Router) -> Self {
        let merged = match self.routes.remove(&kind) {
            Some(existing) => existing.merge(router),
            None => router,
        };
        self.routes.insert(kind, merged);
        self
    }

    /// Replaces the source of interface addresses (for tests).
    #[must_use]
    pub fn with_addr_source(mut self, addrs: AddrSource) -> Self {
        self.addrs = addrs;
        self
    }

    /// Replaces the supervisor timings (for tests).
    #[must_use]
    pub fn with_tuning(mut self, tuning: Tuning) -> Self {
        self.tuning = tuning;
        self
    }

    /// Starts every listener. Must be called inside a Tokio runtime.
    /// Listeners that cannot bind yet keep retrying in the background.
    pub fn start(mut self) -> RunningServer {
        let health = Arc::new(Health::new(self.config.listeners.iter().map(|l| l.kind)));
        let (phase_tx, phase_rx) = watch::channel(Phase::Running);
        let (drain_tx, drain_rx) = mpsc::channel::<()>(1);
        let mut supervisors = JoinSet::new();
        for settings in self.config.listeners.clone() {
            let Some(tls) = self.prepared.tls.get(&settings.kind).cloned() else {
                // `prepare` builds one configuration per listener.
                continue;
            };
            let state = http::AppState {
                health: health.clone(),
                detailed_health: settings.kind == ListenerKind::Metrics,
            };
            let mut router = http::routes(state);
            if let Some(extra) = self.routes.remove(&settings.kind) {
                router = router.merge(extra);
            }
            let router = http::apply_stack(router, &settings);
            let (h1, h2) = http_builders(self.tuning.request_head_timeout);
            let ctx = Arc::new(ListenerCtx {
                conn_limit: Arc::new(Semaphore::new(settings.max_connections)),
                settings,
                acceptor: TlsAcceptor::from(tls),
                router,
                h1,
                h2,
                request_head_timeout: self.tuning.request_head_timeout,
            });
            supervisors.spawn(supervise(Supervisor {
                ctx,
                profile: self.config.profile,
                health: health.clone(),
                addrs: self.addrs.clone(),
                tuning: self.tuning,
                phase: phase_rx.clone(),
                drain: drain_tx.clone(),
            }));
        }
        RunningServer {
            health,
            phase: phase_tx,
            supervisors,
            drain_tx,
            drain_rx,
            grace: self.config.shutdown_grace,
        }
    }
}

/// The HTTP/1.1-only and HTTP/2-only connection builders.
fn http_builders(
    head_timeout: Duration,
) -> (auto::Builder<TokioExecutor>, auto::Builder<TokioExecutor>) {
    let mut h1 = auto::Builder::new(TokioExecutor::new()).http1_only();
    h1.http1()
        .timer(TokioTimer::new())
        .header_read_timeout(head_timeout)
        .max_buf_size(H1_MAX_BUF);
    let mut h2 = auto::Builder::new(TokioExecutor::new()).http2_only();
    h2.http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(H2_MAX_STREAMS)
        .max_header_list_size(H2_MAX_HEADER_LIST)
        .keep_alive_interval(H2_KEEPALIVE_INTERVAL)
        .keep_alive_timeout(H2_KEEPALIVE_TIMEOUT);
    (h1, h2)
}

/// How shutdown ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownOutcome {
    /// Every connection closed within the grace period.
    Drained,
    /// The grace period ran out and the remaining connections were dropped.
    Forced,
}

/// A started server.
pub struct RunningServer {
    health: Arc<Health>,
    phase: watch::Sender<Phase>,
    supervisors: JoinSet<()>,
    drain_tx: mpsc::Sender<()>,
    drain_rx: mpsc::Receiver<()>,
    grace: Duration,
}

impl RunningServer {
    /// The shared health state.
    pub fn health(&self) -> &Arc<Health> {
        &self.health
    }

    /// Shuts down: stop accepting, drain within the grace period, then
    /// drop what is left.
    pub async fn shutdown(self) -> ShutdownOutcome {
        let Self {
            health,
            phase,
            mut supervisors,
            drain_tx,
            mut drain_rx,
            grace,
        } = self;
        tracing::info!(
            grace_secs = grace.as_secs(),
            "shutdown started; draining connections"
        );
        health.set_shutting_down();
        phase.send_replace(Phase::Draining);
        while supervisors.join_next().await.is_some() {}
        drop(drain_tx);
        // `recv` returns `None` once every connection has dropped its
        // sender, that is, once every connection is closed.
        if tokio::time::timeout(grace, drain_rx.recv()).await.is_ok() {
            tracing::info!("all connections closed");
            return ShutdownOutcome::Drained;
        }
        tracing::warn!(
            grace_secs = grace.as_secs(),
            "grace period ended with connections still open; dropping them"
        );
        phase.send_replace(Phase::Force);
        let _ = tokio::time::timeout(FORCE_SETTLE, drain_rx.recv()).await;
        ShutdownOutcome::Forced
    }
}

struct ListenerCtx {
    settings: ListenerSettings,
    acceptor: TlsAcceptor,
    router: Router,
    h1: auto::Builder<TokioExecutor>,
    h2: auto::Builder<TokioExecutor>,
    request_head_timeout: Duration,
    conn_limit: Arc<Semaphore>,
}

struct Supervisor {
    ctx: Arc<ListenerCtx>,
    profile: Profile,
    health: Arc<Health>,
    addrs: AddrSource,
    tuning: Tuning,
    phase: watch::Receiver<Phase>,
    drain: mpsc::Sender<()>,
}

async fn wait_not_running(phase: &mut watch::Receiver<Phase>) {
    // An error means the sender is gone, which also means stop.
    let _ = phase.wait_for(|p| *p != Phase::Running).await;
}

async fn supervise(mut sv: Supervisor) {
    let kind = sv.ctx.settings.kind;
    let bind = sv.ctx.settings.bind.clone();
    let port = sv.ctx.settings.port;
    // The interface list is only needed to resolve an interface name, or to
    // see what a wildcard is reachable on under the overlay profile.
    let needs_host = match &bind {
        BindTarget::Interface(_) => true,
        BindTarget::Ip(ip) => sv.profile == Profile::Overlay && ip.is_unspecified(),
    };
    let mut loops: BTreeMap<SocketAddr, AbortHandle> = BTreeMap::new();
    let mut tasks = JoinSet::new();
    let mut last_failures: Vec<String> = Vec::new();
    let mut last_exposed: Vec<IpAddr> = Vec::new();
    let mut delay = sv.tuning.retry_min;

    loop {
        // Accept loops that ended on their own (they only do on shutdown)
        // are reaped, so their address is bound again if still wanted.
        while let Some(done) = tasks.try_join_next() {
            let _ = done;
        }
        loops.retain(|_, h| !h.is_finished());

        let host = if needs_host {
            let source = sv.addrs.clone();
            match tokio::task::spawn_blocking(move || source()).await {
                Ok(Ok(h)) => h,
                Ok(Err(e)) => {
                    tracing::warn!(listener = %kind, error = %e, "cannot list network interfaces");
                    Vec::new()
                }
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };
        let wanted = net::resolve(&bind, port, &host);

        loops.retain(|addr, h| {
            let keep = wanted.contains(addr);
            if !keep {
                tracing::info!(listener = %kind, address = %addr, "address no longer present; stopped accepting on it");
                h.abort();
            }
            keep
        });

        let mut failures = Vec::new();
        for addr in &wanted {
            if loops.contains_key(addr) {
                continue;
            }
            match bind_socket(*addr) {
                Ok(listener) => {
                    tracing::info!(listener = %kind, address = %addr, "listening");
                    let h = tasks.spawn(accept_loop(
                        listener,
                        sv.ctx.clone(),
                        sv.phase.clone(),
                        sv.drain.clone(),
                    ));
                    loops.insert(*addr, h);
                }
                Err(e) => failures.push(format!("{addr}: {e}")),
            }
        }
        if wanted.is_empty() {
            failures.push(format!("{bind} has no usable address"));
        }
        if failures != last_failures {
            if !failures.is_empty() {
                tracing::warn!(
                    listener = %kind,
                    problems = failures.join("; "),
                    "listener not fully bound; retrying with backoff"
                );
            } else if !last_failures.is_empty() {
                tracing::info!(listener = %kind, "listener fully bound");
            }
            last_failures.clone_from(&failures);
        }

        let bound: BTreeSet<SocketAddr> = loops.keys().copied().collect();
        let exposed = if sv.profile == Profile::Overlay {
            public_addrs(&bound, &host)
        } else {
            Vec::new()
        };
        if exposed != last_exposed {
            if !exposed.is_empty() {
                tracing::warn!(
                    listener = %kind,
                    addresses = join_ips(&exposed),
                    "listener is reachable on a public address under deployment.profile = \"overlay\""
                );
            }
            last_exposed.clone_from(&exposed);
        }
        sv.health.set_listener(
            kind,
            ListenerHealth {
                bound,
                unbound: !failures.is_empty(),
                public_exposure: !exposed.is_empty(),
            },
        );

        let wait = if failures.is_empty() {
            delay = sv.tuning.retry_min;
            sv.tuning.poll
        } else {
            let d = delay;
            delay = delay.saturating_mul(2).min(sv.tuning.retry_max);
            d
        };
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = wait_not_running(&mut sv.phase) => break,
        }
    }

    // Accept loops watch the phase too; wait for them to release their
    // sockets before reporting the listener stopped.
    while tasks.join_next().await.is_some() {}
}

/// Binds a listening socket. IPv6 sockets are IPv6-only, so `::` never
/// silently covers IPv4 too. On Windows, `SO_REUSEADDR` is left off because
/// there it lets another process take over the port. Setting
/// `SO_EXCLUSIVEADDRUSE`, which also stops another process from binding a
/// more specific address on the same port, is part of the server hardening
/// in #229.
fn bind_socket(addr: SocketAddr) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(BACKLOG)?;
    TcpListener::from_std(socket.into())
}

/// Accepts connections on one socket. A connection is accepted first and a
/// connection slot acquired second, so an idle socket never holds a slot.
/// While no slot is free the loop holds at most that one accepted
/// connection, untouched, and stops accepting; other clients wait in the
/// TCP backlog.
async fn accept_loop(
    listener: TcpListener,
    ctx: Arc<ListenerCtx>,
    mut phase: watch::Receiver<Phase>,
    drain: mpsc::Sender<()>,
) {
    let kind = ctx.settings.kind;
    loop {
        let (stream, peer) = tokio::select! {
            r = listener.accept() => match r {
                Ok(v) => v,
                Err(e) => {
                    // Usually a client that went away before it was
                    // accepted, or a descriptor limit; pause briefly so a
                    // persistent error cannot spin.
                    tracing::debug!(listener = %kind, error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            () = wait_not_running(&mut phase) => return,
        };
        let permit = tokio::select! {
            p = ctx.conn_limit.clone().acquire_owned() => match p {
                Ok(p) => p,
                Err(_) => return,
            },
            () = wait_not_running(&mut phase) => return,
        };
        let _ = stream.set_nodelay(true);
        tokio::spawn(serve_connection(
            stream,
            peer,
            ctx.clone(),
            phase.clone(),
            permit,
            drain.clone(),
        ));
    }
}

async fn serve_connection(
    stream: TcpStream,
    peer: SocketAddr,
    ctx: Arc<ListenerCtx>,
    mut phase: watch::Receiver<Phase>,
    _permit: OwnedSemaphorePermit,
    _drain: mpsc::Sender<()>,
) {
    let kind = ctx.settings.kind;
    let tls = tokio::select! {
        r = tokio::time::timeout(HANDSHAKE_TIMEOUT, ctx.acceptor.accept(stream)) => match r {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::debug!(listener = %kind, peer = %peer, error = %e, "TLS handshake failed");
                return;
            }
            Err(_) => {
                tracing::debug!(listener = %kind, peer = %peer, "TLS handshake timed out");
                return;
            }
        },
        () = wait_not_running(&mut phase) => return,
    };
    // The protocol follows ALPN (RFC 7301): `h2` means HTTP/2, anything
    // else HTTP/1.1. The client cannot switch by sending another preface.
    let builder = if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
        &ctx.h2
    } else {
        &ctx.h1
    };
    // Set when the first request reaches the router. Until then the
    // connection is on a deadline, which also covers the HTTP/2 preface and
    // settings exchange that hyper does not time.
    let started = Arc::new(AtomicBool::new(false));
    let seen = started.clone();
    let service = ctx.router.clone().map_request(move |mut req: Request<_>| {
        seen.store(true, Ordering::Relaxed);
        req.extensions_mut().insert(Peer(peer));
        req
    });
    let conn = builder.serve_connection(TokioIo::new(tls), TowerToHyperService::new(service));
    tokio::pin!(conn);
    let first_request = tokio::time::sleep(ctx.request_head_timeout);
    tokio::pin!(first_request);
    let mut draining = false;
    match *phase.borrow_and_update() {
        Phase::Running => {}
        Phase::Draining => {
            draining = true;
            conn.as_mut().graceful_shutdown();
        }
        Phase::Force => return,
    }
    loop {
        tokio::select! {
            r = conn.as_mut() => {
                if let Err(e) = r {
                    tracing::debug!(listener = %kind, peer = %peer, error = %e, "connection ended with an error");
                }
                break;
            }
            () = &mut first_request, if !started.load(Ordering::Relaxed) => {
                if !started.load(Ordering::Relaxed) {
                    tracing::debug!(listener = %kind, peer = %peer, "no request before the request-head timeout; closing");
                    break;
                }
            }
            changed = phase.changed() => {
                if changed.is_err() {
                    break;
                }
                match *phase.borrow_and_update() {
                    Phase::Draining if !draining => {
                        draining = true;
                        conn.as_mut().graceful_shutdown();
                    }
                    Phase::Force => break,
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::load_str;
    use std::path::Path;

    fn config(profile: &str, admin_bind: &str, metrics_bind: &str) -> Config {
        let text = format!(
            r#"
            [deployment]
            profile = "{profile}"
            [tls]
            cert_file = "c"
            key_file = "k"
            [listen.admin]
            bind = "{admin_bind}"
            port = 8443
            [listen.agent]
            bind = "overlay0"
            port = 8444
            client_ca_file = "ca"
            [listen.metrics]
            bind = "{metrics_bind}"
            "#
        );
        load_str(&text, "t", Path::new("/"), &[]).unwrap().config
    }

    fn host() -> Vec<HostAddr> {
        let a = |i: &str, ip: &str| HostAddr {
            interface: i.into(),
            ip: ip.parse().unwrap(),
            scope_id: 0,
        };
        vec![
            a("lo", "127.0.0.1"),
            a("eth0", "8.8.4.4"),
            a("overlay0", "100.64.0.7"),
        ]
    }

    #[test]
    fn standard_profile_has_no_placement_warnings() {
        let c = config("standard", "0.0.0.0", "0.0.0.0");
        assert!(placement_warnings(&c, &host()).is_empty());
    }

    #[test]
    fn overlay_profile_flags_wildcard_public_and_metrics() {
        let c = config("overlay", "0.0.0.0", "0.0.0.0");
        let w = placement_warnings(&c, &host());
        let joined = w.join("\n");
        assert!(
            joined.contains("listen.admin: binds every interface"),
            "{joined}"
        );
        assert!(
            joined.contains("listen.admin: reachable on public address(es) 8.8.4.4"),
            "{joined}"
        );
        assert!(
            joined.contains("listen.metrics: not bound to loopback"),
            "{joined}"
        );
        assert!(!joined.contains("listen.agent"), "{joined}");
    }

    #[test]
    fn overlay_profile_clean_layout() {
        let c = config("overlay", "100.64.0.7", "127.0.0.1");
        assert!(placement_warnings(&c, &host()).is_empty());
    }

    #[test]
    fn overlay_profile_reports_missing_interface() {
        let c = config("overlay", "100.64.0.7", "127.0.0.1");
        let w = placement_warnings(&c, &host()[..2]);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("interface overlay0 has no address now"));
    }
}
