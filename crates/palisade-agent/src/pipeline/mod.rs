//! The agent event pipeline (#63, #197).
//!
//! Every event the agent produces goes through one pipeline: it is
//! numbered and chained, de-duplicated or summarised by type and policy,
//! throttled with explicit signals, spooled durably on disk, and uploaded
//! in batches with acknowledgements, replayed after offline periods.
//!
//! This module has the durable parts:
//!
//! - [`segment`]: the spool's segment file format and its reader, which is
//!   written for untrusted bytes and fuzzed (`spool_segment`).
//! - [`storage`]: where segments live, on disk or in memory.
//! - [`spool`]: the spool itself, with recovery, caps, eviction by
//!   priority, expiry and acknowledgement.
//!
//! The agent local store (ADR 0007) is still a proposal, so the spool is a
//! small, auditable segment log behind the [`spool::Spool`] trait, which a
//! store-backed spool can implement later.

#![forbid(unsafe_code)]

pub mod crc32c;
pub mod segment;
pub mod spool;
pub mod storage;
