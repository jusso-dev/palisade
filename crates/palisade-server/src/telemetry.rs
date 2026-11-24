//! Structured logging.
//!
//! `serve` writes one JSON object per line to standard error, with the
//! timestamp, level, target, message, fields, and the fields of the current
//! request span (`request_id`, `listener`, `method`, `route`, `peer`).
//! Tenant and principal fields join the request span with #185 and #130;
//! changing the level at runtime arrives with the admin API.
//!
//! No secret value is ever passed to a log macro: the configuration holds
//! secret paths only, and the secret reader's errors never include file
//! contents. The redaction layer for field names in #227 adds a second line
//! of defence.

use tracing::level_filters::LevelFilter;

/// Installs the JSON subscriber as the global default, and a panic hook
/// that logs panics through it, so standard error carries JSON lines only.
/// Returns an error if a global subscriber is already set.
pub fn init_json(level: LevelFilter) -> Result<(), String> {
    tracing_subscriber::fmt()
        .json()
        .with_max_level(level)
        .with_current_span(true)
        .with_span_list(false)
        .with_writer(std::io::stderr)
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
