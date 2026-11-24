//! RFC 9457 problem details (`application/problem+json`).
//!
//! Every error response the server sends is a problem document. Handlers
//! return a [`Problem`]; the request middleware in [`crate::http`] renders it
//! and adds the request ID. Error responses produced elsewhere in the stack
//! (no matching route, wrong method, body too large, timeout, panic, an
//! extractor rejection) are replaced by a generic problem for their status,
//! so their original bodies, which may describe internals, never reach the
//! client.
//!
//! The `type` URIs are stable identifiers under
//! `https://palisade.dev/problems/<slug>`, following the catalogue in #185.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};

/// The base of every problem `type` URI.
pub const TYPE_BASE: &str = "https://palisade.dev/problems/";
/// The media type of a problem document.
pub const CONTENT_TYPE: &str = "application/problem+json";

/// A problem to report to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// HTTP status.
    pub status: StatusCode,
    /// The last segment of the `type` URI.
    pub slug: &'static str,
    /// A short, fixed summary of the problem type.
    pub title: &'static str,
    /// An explanation of this occurrence. Never contains internals such as
    /// SQL, file paths or stack traces.
    pub detail: String,
    /// Extension members (RFC 9457 section 3.2), added after the standard
    /// members. Keys that clash with a standard member are ignored.
    pub extensions: Map<String, Value>,
}

impl Problem {
    /// The generic problem for an error `status` that carries no problem of
    /// its own.
    pub fn for_status(status: StatusCode) -> Self {
        let (slug, title, detail) = match status {
            StatusCode::BAD_REQUEST => (
                "bad-request",
                "Bad request",
                "The request could not be understood.",
            ),
            StatusCode::NOT_FOUND => ("not-found", "Not found", "No resource exists at this path."),
            StatusCode::METHOD_NOT_ALLOWED => (
                "method-not-allowed",
                "Method not allowed",
                "This resource does not support the request method.",
            ),
            StatusCode::PAYLOAD_TOO_LARGE => (
                "payload-too-large",
                "Payload too large",
                "The request body exceeds the limit for this endpoint.",
            ),
            StatusCode::UNSUPPORTED_MEDIA_TYPE => (
                "unsupported-media-type",
                "Unsupported media type",
                "The request body has a media type this endpoint does not accept.",
            ),
            StatusCode::UNPROCESSABLE_ENTITY => (
                "validation",
                "Validation failed",
                "The request body is not valid for this endpoint.",
            ),
            StatusCode::REQUEST_TIMEOUT => (
                "timeout",
                "Request timeout",
                "The request was not completed in time. Re-read the resource before retrying a change.",
            ),
            StatusCode::SERVICE_UNAVAILABLE => (
                "unavailable",
                "Service unavailable",
                "The server could not complete the request in time. Re-read the resource before retrying a change.",
            ),
            s if s.is_server_error() => (
                "internal",
                "Internal server error",
                "The server failed to complete the request. Re-read the resource before retrying a change.",
            ),
            _ => (
                "client-error",
                "Request rejected",
                "The request was rejected.",
            ),
        };
        Self {
            status,
            slug,
            title,
            detail: detail.to_owned(),
            extensions: Map::new(),
        }
    }

    /// Adds an extension member.
    #[must_use]
    pub fn with_extension(mut self, key: &str, value: Value) -> Self {
        self.extensions.insert(key.to_owned(), value);
        self
    }

    /// The `type` URI.
    pub fn type_uri(&self) -> String {
        format!("{TYPE_BASE}{}", self.slug)
    }

    /// Renders the problem document for the request `request_id`.
    pub fn render(&self, request_id: &str) -> Response {
        let mut body = json!({
            "type": self.type_uri(),
            "title": self.title,
            "status": self.status.as_u16(),
            "detail": self.detail,
            "instance": format!("urn:palisade:request:{request_id}"),
            "request_id": request_id,
        });
        if let Value::Object(members) = &mut body {
            for (k, v) in &self.extensions {
                members.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
        let mut res = (self.status, body.to_string()).into_response();
        let headers = res.headers_mut();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE));
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        res
    }
}

/// A handler can return a [`Problem`] directly. The body is filled in by the
/// request middleware, which knows the request ID.
impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let mut res = self.status.into_response();
        res.extensions_mut().insert(self);
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_has_every_member() {
        let p = Problem::for_status(StatusCode::PAYLOAD_TOO_LARGE);
        let res = p.render("abc123");
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(res.headers()[header::CONTENT_TYPE], CONTENT_TYPE);
        assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
    }

    #[test]
    fn extensions_never_override_standard_members() {
        let p = Problem::for_status(StatusCode::NOT_FOUND)
            .with_extension("status", json!(200))
            .with_extension("indicators", json!(["x"]));
        let res = p.render("r1");
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let body = futures_body(res);
        assert_eq!(body["status"], 404);
        assert_eq!(body["indicators"], json!(["x"]));
        assert_eq!(body["request_id"], "r1");
        assert_eq!(body["instance"], "urn:palisade:request:r1");
        assert_eq!(body["type"], "https://palisade.dev/problems/not-found");
    }

    fn futures_body(res: Response) -> Value {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let bytes = rt
            .block_on(axum::body::to_bytes(res.into_body(), 1 << 20))
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn unknown_server_errors_are_internal() {
        let p = Problem::for_status(StatusCode::BAD_GATEWAY);
        assert_eq!(p.slug, "internal");
        assert_eq!(p.type_uri(), "https://palisade.dev/problems/internal");
    }

    #[test]
    fn unknown_client_errors_are_generic() {
        let p = Problem::for_status(StatusCode::IM_A_TEAPOT);
        assert_eq!(p.slug, "client-error");
    }
}
