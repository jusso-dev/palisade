//! The agent event pipeline (#63, #197).
//!
//! Every event the agent produces goes through one pipeline: it is
//! numbered and chained, de-duplicated or summarised by type and policy,
//! throttled with explicit signals, spooled durably on disk, and uploaded
//! in batches with acknowledgements, replayed after offline periods.
//!
//! - [`intake`]: the producers' non-blocking handle, with a priority and a
//!   bulk queue, and the adapters for the process monitor (#59), event-log
//!   ingest (#58) and the policy cache (#61).
//! - [`aggregate`]: classification, allowed-execution summaries,
//!   first-seen and de-duplication with exact counts.
//! - [`throttle`]: the per-agent quota with watermarks.
//! - [`chain`]: sequence numbers and the hash chain.
//! - [`core`]: the [`core::Pipeline`] that ties them together and reports
//!   every loss as `agent.dropped`.
//! - [`segment`]: the spool's segment file format and its reader, which is
//!   written for untrusted bytes and fuzzed (`spool_segment`).
//! - [`storage`]: where segments live, on disk or in memory.
//! - [`spool`]: the spool itself, with recovery, caps, eviction by
//!   priority, expiry and acknowledgement.
//! - [`upload`]: the [`upload::Uploader`] trait that server communication
//!   (#62) implements, batching, acknowledgement and rate-limited replay.
//! - [`subsystem`]: the `event-pipeline` subsystem.
//!
//! The agent local store (ADR 0007) is still a proposal, so the spool is a
//! small, auditable segment log behind the [`spool::Spool`] trait, which a
//! store-backed spool can implement later.

#![forbid(unsafe_code)]

pub mod aggregate;
pub mod chain;
pub mod core;
pub mod crc32c;
pub mod intake;
pub mod segment;
pub mod spool;
pub mod storage;
pub mod subsystem;
#[cfg(test)]
mod testing;
pub mod throttle;
pub mod upload;

use palisade_proto::events::Uuid7;

/// A fixed UUIDv7 ending in `n`: placeholders the pipeline replaces.
#[must_use]
pub const fn fixed_uuid(n: u8) -> Uuid7 {
    match Uuid7::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, n]) {
        Some(id) => id,
        // The version and variant bits above are always valid.
        None => panic!("a fixed UUIDv7"),
    }
}
