//! The axum router and the tower middleware stack for one listener.
//!
//! Layers, outermost first:
//!
//! 1. **Request ID and error normalisation.** Accepts a well-formed
//!    `Palisade-Request-Id` from the client or generates a random one,
//!    echoes it on the response, and turns every error response into an
//!    RFC 9457 problem document (see [`crate::problem`]).
//! 2. **Trace.** One span per request with `request_id`, `listener`,
//!    `method` and the matched `route` template (never the raw path or
//!    query, which may carry tokens), and one log line per response with the
//!    status and latency.
//! 3. **Panic guard.** A panicking handler becomes a 500 problem; the panic
//!    message stays in the server log.
//! 4. **Timeout.** A handler that runs past the listener's
//!    `request_timeout_secs` is cancelled with a 503 problem.
//! 5. **Body limit.** A body larger than the listener's `body_limit_bytes`
//!    gets a 413 problem, whether the size is declared up front or only
//!    discovered while streaming.
//!
//! Tenant, principal, authentication, rate-limit, CORS and compression
//! layers join this stack with the API work in #185, #130 and #229.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::extract::{DefaultBodyLimit, MatchedPath, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::json;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::Span;

use crate::config::ListenerSettings;
use crate::health::Health;
use crate::problem::Problem;

/// The request ID header, accepted from clients and set on every response.
pub const REQUEST_ID: HeaderName = HeaderName::from_static("palisade-request-id");
/// Longest client-supplied request ID that is accepted as is.
const MAX_REQUEST_ID: usize = 64;

/// Headers from an original error response that survive normalisation.
const KEPT_ERROR_HEADERS: [HeaderName; 3] =
    [header::ALLOW, header::RETRY_AFTER, header::WWW_AUTHENTICATE];

/// The request ID of the current request, available as a request
/// extension to every layer and handler inside the first one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(pub String);

/// The remote address of the connection, inserted by the listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer(pub SocketAddr);

/// State shared by the handlers of one listener.
#[derive(Debug, Clone)]
pub struct AppState {
    /// Server health.
    pub health: Arc<Health>,
    /// Whether `/readyz` includes the indicator list. Only the metrics
    /// listener, which binds to loopback by default, shows it.
    pub detailed_health: bool,
}

/// The routes of a listener, without middleware. Every listener serves the
/// probes. Agent, API and metrics routes arrive with #62, #185 and the
/// metrics work in #126.
pub fn routes(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(state)
}

/// Wraps `router` in the middleware stack, configured for `settings`.
pub fn apply_stack(router: Router, settings: &ListenerSettings) -> Router {
    let listener = settings.kind.name();
    let trace = TraceLayer::new_for_http()
        .make_span_with(move |req: &Request| {
            let id = req
                .extensions()
                .get::<RequestId>()
                .map_or("", |r| r.0.as_str());
            let route = req
                .extensions()
                .get::<MatchedPath>()
                .map_or("unmatched", MatchedPath::as_str);
            let peer = req
                .extensions()
                .get::<Peer>()
                .map(|p| p.0.to_string())
                .unwrap_or_default();
            tracing::info_span!(
                "request",
                request_id = id,
                listener,
                method = %req.method(),
                route,
                peer,
            )
        })
        .on_request(())
        .on_response(|res: &Response, latency: Duration, _span: &Span| {
            let status = res.status().as_u16();
            let latency_ms = u64::try_from(latency.as_millis()).unwrap_or(u64::MAX);
            if res.status().is_server_error() {
                tracing::warn!(status, latency_ms, "request failed");
            } else if res.status().is_success() {
                // Successful probes arrive every few seconds; keep them out
                // of the default log level.
                tracing::debug!(status, latency_ms, "request completed");
            } else {
                tracing::info!(status, latency_ms, "request completed");
            }
        })
        .on_body_chunk(())
        .on_eos(())
        .on_failure(());
    // `Router::layer` wraps every route and the fallback, innermost first,
    // and converts each layer's response back into an axum response.
    router
        .layer(DefaultBodyLimit::max(settings.body_limit))
        .layer(RequestBodyLimitLayer::new(settings.body_limit))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            settings.request_timeout,
        ))
        .layer(CatchPanicLayer::custom(|_panic| {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }))
        .layer(trace)
        .layer(middleware::from_fn(request_id_and_problems))
}

/// The first layer: assigns the request ID and normalises errors.
async fn request_id_and_problems(mut req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get(&REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|v| valid_request_id(v))
        .map_or_else(new_request_id, str::to_owned);
    req.extensions_mut().insert(RequestId(id.clone()));

    let res = next.run(req).await;
    let mut res = normalise(res, &id);
    let headers = res.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&id) {
        headers.insert(REQUEST_ID, v);
    }
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    res
}

/// Replaces an error response with its problem document. A response that
/// carries a [`Problem`] is rendered from it. Any other error response is
/// replaced by the generic problem for its status, keeping only the headers
/// in [`KEPT_ERROR_HEADERS`].
fn normalise(res: Response, request_id: &str) -> Response {
    if let Some(problem) = res.extensions().get::<Problem>() {
        let mut out = problem.render(request_id);
        copy_kept_headers(res.headers(), out.headers_mut());
        return out;
    }
    let status = res.status();
    if !(status.is_client_error() || status.is_server_error()) {
        return res;
    }
    let mut out = Problem::for_status(status).render(request_id);
    copy_kept_headers(res.headers(), out.headers_mut());
    out
}

fn copy_kept_headers(from: &HeaderMap, to: &mut HeaderMap) {
    for name in KEPT_ERROR_HEADERS {
        for v in from.get_all(&name) {
            to.append(name.clone(), v.clone());
        }
    }
}

/// A client-supplied request ID is used only if it is 1 to 64 characters of
/// `A-Z a-z 0-9 . _ : -`, so it cannot inject into logs or headers.
fn valid_request_id(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= MAX_REQUEST_ID
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// 128 random bits, hex encoded.
fn new_request_id() -> String {
    static FALLBACK: AtomicU64 = AtomicU64::new(0);
    let mut bytes = [0u8; 16];
    if SystemRandom::new().fill(&mut bytes).is_err() {
        // The OS random source failed. IDs only correlate log lines, so a
        // process-local counter is an acceptable stand-in.
        return format!("local-{}", FALLBACK.fetch_add(1, Ordering::Relaxed));
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn healthz() -> Response {
    (
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(json!({ "status": "alive" })),
    )
        .into_response()
}

async fn readyz(State(state): State<AppState>) -> Response {
    let r = state.health.readiness();
    let status = r.body["status"].clone();
    let indicators = r.body["indicators"].clone();
    if r.ready {
        let body = if state.detailed_health {
            r.body
        } else {
            json!({ "status": status })
        };
        return ([(header::CACHE_CONTROL, "no-store")], axum::Json(body)).into_response();
    }
    let mut problem = Problem {
        status: StatusCode::SERVICE_UNAVAILABLE,
        slug: "not-ready",
        title: "Not ready",
        detail: "The server is not ready to serve traffic.".to_owned(),
        extensions: serde_json::Map::new(),
    }
    .with_extension("readiness", status);
    if state.detailed_health {
        problem = problem.with_extension("indicators", indicators);
    }
    problem.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BindTarget, ListenerKind};
    use crate::health::ListenerHealth;
    use axum::body::Body;
    use serde_json::Value;
    use tower::ServiceExt;

    fn settings(kind: ListenerKind) -> ListenerSettings {
        ListenerSettings {
            kind,
            bind: BindTarget::Ip([127, 0, 0, 1].into()),
            port: 1,
            public_url: None,
            body_limit: 16,
            request_timeout: Duration::from_millis(200),
            max_connections: 1,
            client_ca_file: None,
        }
    }

    fn app(kind: ListenerKind, health: Arc<Health>) -> Router {
        let state = AppState {
            health,
            detailed_health: kind == ListenerKind::Metrics,
        };
        let extra = Router::new()
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    "late"
                }),
            )
            .route(
                "/panic",
                get(|| async {
                    if std::hint::black_box(true) {
                        panic!("secret internal detail");
                    }
                    "unreachable"
                }),
            )
            .route(
                "/echo",
                axum::routing::post(|body: axum::body::Bytes| async move { body }),
            )
            .route(
                "/raw-error",
                get(|| async { (StatusCode::BAD_GATEWAY, "upstream at 10.0.0.5 said no") }),
            );
        apply_stack(routes(state).merge(extra), &settings(kind))
    }

    fn ready_health() -> Arc<Health> {
        let h = Arc::new(Health::new([ListenerKind::Admin]));
        h.set_listener(ListenerKind::Admin, ListenerHealth::default());
        h
    }

    async fn send(app: Router, req: Request<Body>) -> (StatusCode, HeaderMap, Value) {
        let res = app.oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, headers, body)
    }

    fn get_req(path: &str) -> Request<Body> {
        Request::get(path).body(Body::empty()).unwrap()
    }

    fn assert_problem(status: StatusCode, headers: &HeaderMap, body: &Value, slug: &str) {
        assert_eq!(headers[header::CONTENT_TYPE], "application/problem+json");
        assert_eq!(body["status"], status.as_u16());
        assert_eq!(
            body["type"],
            format!("https://palisade.dev/problems/{slug}")
        );
        let id = headers[&REQUEST_ID].to_str().unwrap();
        assert_eq!(body["request_id"], id);
        assert_eq!(body["instance"], format!("urn:palisade:request:{id}"));
        assert!(body["title"].is_string() && body["detail"].is_string());
    }

    #[tokio::test]
    async fn healthz_is_alive() {
        let (s, h, b) = send(
            app(ListenerKind::Admin, ready_health()),
            get_req("/healthz"),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(b, json!({ "status": "alive" }));
        assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(h[&REQUEST_ID].len(), 32);
    }

    #[tokio::test]
    async fn readyz_detail_only_on_metrics() {
        let health = Arc::new(Health::new([ListenerKind::Admin]));
        let (s, h, b) = send(app(ListenerKind::Admin, health.clone()), get_req("/readyz")).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
        assert_problem(s, &h, &b, "not-ready");
        assert_eq!(b["readiness"], "degraded");
        assert!(b.get("indicators").is_none());

        let (s, _, b) = send(
            app(ListenerKind::Metrics, health.clone()),
            get_req("/readyz"),
        )
        .await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(b["indicators"], json!(["listener_unbound:admin"]));

        health.set_listener(ListenerKind::Admin, ListenerHealth::default());
        let (s, _, b) = send(app(ListenerKind::Admin, health.clone()), get_req("/readyz")).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(b, json!({ "status": "ready" }));
    }

    #[tokio::test]
    async fn not_found_is_a_problem() {
        let (s, h, b) = send(
            app(ListenerKind::Admin, ready_health()),
            get_req("/nope?token=x"),
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_problem(s, &h, &b, "not-found");
    }

    #[tokio::test]
    async fn wrong_method_keeps_allow_header() {
        let req = Request::delete("/healthz").body(Body::empty()).unwrap();
        let (s, h, b) = send(app(ListenerKind::Admin, ready_health()), req).await;
        assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED);
        assert_problem(s, &h, &b, "method-not-allowed");
        assert!(h.contains_key(header::ALLOW));
    }

    #[tokio::test]
    async fn declared_oversize_body_is_413() {
        let req = Request::post("/echo")
            .header(header::CONTENT_LENGTH, "17")
            .body(Body::from(vec![0u8; 17]))
            .unwrap();
        let (s, h, b) = send(app(ListenerKind::Admin, ready_health()), req).await;
        assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
        assert_problem(s, &h, &b, "payload-too-large");
    }

    #[tokio::test]
    async fn body_within_limit_passes() {
        let req = Request::post("/echo")
            .body(Body::from("0123456789"))
            .unwrap();
        let res = app(ListenerKind::Admin, ready_health())
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn slow_handler_times_out() {
        let (s, h, b) = send(app(ListenerKind::Admin, ready_health()), get_req("/slow")).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
        assert_problem(s, &h, &b, "unavailable");
    }

    #[tokio::test]
    async fn panic_is_500_without_detail() {
        let (s, h, b) = send(app(ListenerKind::Admin, ready_health()), get_req("/panic")).await;
        assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
        assert_problem(s, &h, &b, "internal");
        assert!(!b.to_string().contains("secret"));
    }

    #[tokio::test]
    async fn raw_error_bodies_are_replaced() {
        let (s, h, b) = send(
            app(ListenerKind::Admin, ready_health()),
            get_req("/raw-error"),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_GATEWAY);
        assert_problem(s, &h, &b, "internal");
        assert!(!b.to_string().contains("10.0.0.5"));
    }

    #[tokio::test]
    async fn client_request_id_is_echoed_only_if_well_formed() {
        let req = Request::get("/nope")
            .header(&REQUEST_ID, "abc-123:x.y_z")
            .body(Body::empty())
            .unwrap();
        let (_, h, b) = send(app(ListenerKind::Admin, ready_health()), req).await;
        assert_eq!(h[&REQUEST_ID], "abc-123:x.y_z");
        assert_eq!(b["request_id"], "abc-123:x.y_z");

        for bad in ["", "has space", "a\"b", &"x".repeat(65)] {
            let req = Request::get("/healthz")
                .header(&REQUEST_ID, HeaderValue::from_str(bad).unwrap())
                .body(Body::empty())
                .unwrap();
            let (_, h, _) = send(app(ListenerKind::Admin, ready_health()), req).await;
            assert_ne!(h[&REQUEST_ID], bad);
            assert_eq!(h[&REQUEST_ID].len(), 32);
        }
    }

    #[test]
    fn generated_ids_differ() {
        assert_ne!(new_request_id(), new_request_id());
    }
}
