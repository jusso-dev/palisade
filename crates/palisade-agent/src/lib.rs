#![doc = include_str!("../README.md")]
// ADR 0011: `unsafe` code only in `ffi` (Windows only), which is on
// `unsafe-allowlist.txt`. The root cannot `forbid` it, since `forbid`
// cannot be relaxed, so it keeps the workspace's `deny`, and every other
// module forbids it at its own root.

pub mod boot;
pub mod cli;
pub mod clock;
pub mod comms;
pub mod config;
pub mod control;
pub mod eventlog;
pub mod facts;
#[cfg(windows)]
mod ffi;
pub mod host;
pub mod inventory;
pub mod lifecycle;
pub mod logfile;
pub mod platform;
pub mod policy_cache;
#[cfg(windows)]
pub mod service;
pub mod settings;
#[cfg(feature = "test-util")]
pub mod simulate;
pub mod subsystem;
pub mod supervisor;
pub mod telemetry;
