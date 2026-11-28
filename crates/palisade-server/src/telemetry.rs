//! Structured logging.
//!
//! `serve` writes one JSON object per line to standard error, with the
//! timestamp, level, target, message and fields, the current span as
//! `span`, and every enclosing span as `spans`, so the request span's
//! `request_id`, `listener`, `method`, `route` and `peer` stay on the line
//! even when a handler opens a child span.
//! Tenant and principal fields join the request span with #185 and #130;
//! changing the level at runtime arrives with the admin API.
//!
//! No secret value is ever passed to a log macro: the configuration holds
//! secret paths only, and the secret reader's errors never include file
//! contents. As a second line of defence, every line goes through
//! [`crate::redact`] on its way out (#227): fields with sensitive names and
//! secret-looking values are replaced by `[REDACTED]`.

use tracing::level_filters::LevelFilter;

use crate::redact::RedactingMakeWriter;

/// Installs the JSON subscriber as the global default, and a panic hook
/// that logs panics through it, so standard error carries JSON lines only.
/// Returns an error if a global subscriber is already set.
pub fn init_json(level: LevelFilter) -> Result<(), String> {
    tracing_subscriber::fmt()
        .json()
        .with_max_level(level)
        .with_current_span(true)
        .with_span_list(true)
        .with_writer(RedactingMakeWriter(std::io::stderr))
        .try_init()
        .map_err(|e| format!("cannot install the log subscriber: {e}"))?;
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        let payload = info.payload();
        let message = payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        tracing::error!(panic.message = message, panic.location = location, "panic");
    }));
    Ok(())
}
